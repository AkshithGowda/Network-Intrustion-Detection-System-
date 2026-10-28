"""Real-time detection engine shared by the console simulator (simulate.py) and the web dashboard (dashboard.py).

Every 0.5 s tick it generates a batch of flows (the "network"), scores them with the trained ensemble + K-Means
detector, raises alerts, and acts like a small firewall: a source that triggers 5 alerts is blocked for a while.
"""
import json
import threading
from collections import Counter, deque
from datetime import datetime, timedelta
from pathlib import Path

import joblib
import numpy as np

from traffic import FEATURES, PROTOCOLS, log_scale, make_flows

ROOT = Path(__file__).resolve().parent
TICK = 0.5               # seconds of simulated time per step
BASE_RATE = 10           # normal flows per second
BLOCK_AFTER = 5          # alerts from one source before the firewall blocks it
BLOCK_TTL = 40           # seconds a block lasts
UNKNOWN_CONF = 0.75      # K-Means says "strange" and the Random Forest is unsure -> unknown attack

PHASES = {               # key: (title, seconds, rate multiplier, traffic mix)
    "normal": ("Normal traffic", 8, 1.0, {"normal": 1}),
    "dos": ("DoS flood", 10, 3.0, {"normal": .4, "dos": .6}),
    "probe": ("Port / path scan", 10, 1.5, {"normal": .5, "probe": .5}),
    "brute_force": ("Login brute force", 10, 1.2, {"normal": .6, "brute_force": .4}),
    "sqli": ("SQL injection attack", 10, 1.2, {"normal": .6, "sqli": .4}),
    "exfil": ("Data exfiltration (bandwidth abuse)", 10, 1.0, {"normal": .7, "exfil": .3}),
    "botnet": ("Unknown attack: botnet beaconing (zero-day)", 12, 1.5, {"normal": .6, "botnet": .4}),
    "flash": ("Flash crowd (legitimate surge, not an attack)", 12, 3.0, {"normal": 1}),
}
LEVELS = {"calm": (25, 60), "normal": (12, 35), "busy": (5, 15)}      # seconds of quiet baseline between random scenarios
ATTACK_KEYS = ["dos", "probe", "brute_force", "sqli", "exfil", "botnet"]
SCENARIO = ["normal", "dos", "normal", "probe", "brute_force", "sqli", "exfil", "botnet", "normal"]
IDLE = ("Baseline traffic", 10 ** 6, 1.0, {"normal": 1})
INTEL = {                # alert type -> (severity, MITRE ATT&CK technique, name)
    "dos": ("high", "T1498", "Network Denial of Service"), "probe": ("medium", "T1595", "Active Scanning"),
    "brute_force": ("high", "T1110", "Brute Force"), "sqli": ("critical", "T1190", "Exploit Public-Facing Application"),
    "exfil": ("critical", "T1048", "Exfiltration Over Alternative Protocol"),
    "unknown": ("high", "T1071", "Application Layer Protocol (C2)"),
}
ATTACKERS = {"dos": [f"203.0.113.{i}" for i in range(10, 16)], "probe": ["198.51.100.23", "198.51.100.24"],
             "brute_force": ["192.0.2.77", "192.0.2.78"], "sqli": ["198.51.100.77", "198.51.100.80"],
             "exfil": ["10.0.7.55"], "botnet": ["10.0.7.31", "10.0.7.32"]}
PORTS = {"dos": [80], "probe": None, "brute_force": [443, 22], "sqli": [443], "exfil": [443], "botnet": [8443]}


class Engine:
    def __init__(self, model_path=ROOT / "models" / "ids.joblib", seed=1):
        b = joblib.load(model_path)
        self.model, self.scaler, self.km, self.thr = b["model"], b["scaler"], b["kmeans"], b["threshold"]
        try:
            self.model.set_params(rf__n_jobs=1, bag__n_jobs=1)       # tiny batches: threads cost more than they save
        except ValueError:
            pass
        self.classes = list(self.model.classes_)
        self.seed = seed
        self.base_rate, self.auto, self.level = BASE_RATE, False, "normal"
        self.run_until, self.finished = None, False                           # timed run: traffic stops at this simulated time
        try:                                                                 # training results, quoted in the attack report
            self.model_meta = json.loads((ROOT / "reports" / "results.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.model_meta = {}
        self.lock = threading.RLock()
        self.reset()

    # ------------------------------------------------------------------ state
    def reset(self):
        with self.lock:
            self.rng = np.random.default_rng(self.seed)
            self.clock = datetime.now().replace(microsecond=0)
            self.eid = 0
            self.events, self.alerts, self.sqli = deque(maxlen=400), deque(maxlen=200), deque(maxlen=60)
            self.series, self.bucket = deque(maxlen=120), None
            self.stat = Counter()
            self.by_type, self.by_src, self.src_alerts = Counter(), Counter(), Counter()
            self.blocked = {}
            self.queue, self.cur, self.paused = deque(), None, False
            self.start_clock = self.clock                                   # history for the attack report
            self.history, self.hist_series = deque(maxlen=60000), deque(maxlen=36000)
            self.fw_log, self.phase_log = [], []
            self.auto_timer = self._gap()

    def _gap(self):
        lo, hi = LEVELS[self.level]
        return float(self.rng.uniform(lo, hi))

    def launch(self, key, **over):
        with self.lock:
            self.queue.append((key, over))

    def run_scenario(self):
        with self.lock:
            self.queue.extend((k, {}) for k in SCENARIO)

    def random_scenario(self):
        """One random scenario with random length, intensity and attack share (or a harmless flash crowd)."""
        with self.lock:
            r = self.rng
            if r.random() < .2:
                self.queue.append(("flash", dict(secs=float(r.uniform(6, 14)), mult=float(r.uniform(2, 4)))))
                return "flash"
            key = ATTACK_KEYS[int(r.integers(len(ATTACK_KEYS)))]
            share = float(r.uniform(.25, .6))
            self.queue.append((key, dict(secs=float(r.uniform(6, 14)), mult=float(PHASES[key][2] * r.uniform(.8, 1.4)), mix={"normal": 1 - share, key: share})))
            return key

    def set_auto(self, on, level=None):
        with self.lock:
            self.auto = bool(on)
            if level in LEVELS:
                self.level = level
            self.auto_timer = self._gap()

    def set_timer(self, minutes=None, until=None, fresh=True):
        """Simulate traffic for `minutes`, or until the clock reads `until` (HH:MM). The run then stops by itself."""
        with self.lock:
            if fresh:
                self.reset()                                                  # counters, history and the report start at zero
            if until:
                hh, mm = (int(x) for x in until.split(":"))
                target = self.clock.replace(hour=hh, minute=mm, second=0, microsecond=0)
                if target <= self.clock:
                    target += timedelta(days=1)
            else:
                target = self.clock + timedelta(minutes=minutes)
            self.run_until, self.finished, self.paused = target, False, False

    def cancel_timer(self):
        with self.lock:
            self.run_until, self.finished, self.paused = None, False, False

    def set_rate(self, value):
        with self.lock:
            self.base_rate = max(2, min(40, int(value)))

    def idle(self):
        with self.lock:
            return not self.queue and (self.cur is None or self.cur["key"] == "idle")

    def unblock_all(self):
        with self.lock:
            self.blocked.clear()
            self.src_alerts.clear()

    def _phase(self):
        if self.cur is None or self.cur["left"] <= 0 or (self.cur["key"] == "idle" and self.queue):
            if self.queue:
                key, over = self.queue.popleft()
                title, secs, mult, mix = PHASES[key]
                secs, mult, mix = over.get("secs", secs), over.get("mult", mult), over.get("mix", mix)
            else:
                key, (title, secs, mult, mix) = "idle", IDLE
            self.cur = dict(key=key, title=title, left=int(secs / TICK), mult=mult, mix=mix)
            self.phase_log.append(dict(ts=self.clock, key=key, title=title))
        return self.cur

    # ------------------------------------------------------------------ one tick
    def step(self):
        with self.lock:
            if self.run_until and self.clock >= self.run_until:
                self.run_until, self.finished, self.paused = None, True, True    # the timed run is over
            if self.paused:
                return []
            if self.auto and not self.queue and (self.cur is None or self.cur["key"] == "idle"):
                self.auto_timer -= TICK                                     # random scenarios: wait a random quiet time, then strike
                if self.auto_timer <= 0:
                    self.random_scenario()
                    self.auto_timer = self._gap()
            ph = self._phase()
            ph["left"] -= 1
            n = int(self.rng.poisson(self.base_rate * ph["mult"] * TICK))
            flows = make_flows(n, ph["mix"], self.rng) if n else None
            self.clock += timedelta(seconds=TICK)
        scored = self._score(flows) if flows is not None else None          # model work outside the lock
        with self.lock:
            out = self._expire()
            out += self._ingest(flows, scored) if flows is not None else []
            self._tick_series(out)
            return out

    def _score(self, flows):
        X = flows[FEATURES]
        proba = self.model.predict_proba(X)
        dist = self.km.transform(self.scaler.transform(log_scale(X))).min(axis=1)
        rf_conf = np.ones(len(X))                                        # forest confidence, only needed for odd-looking flows
        odd = dist > self.thr
        if odd.any():
            rf_conf[odd] = self.model.named_estimators_["rf"].predict_proba(X[odd]).max(1)
        return np.array(self.classes)[proba.argmax(1)], proba.max(1), dist, rf_conf

    def _endpoint(self, label):
        r = self.rng
        if label == "normal":
            return f"10.0.{r.integers(0, 4)}.{r.integers(2, 250)}", f"10.0.9.{r.integers(1, 4)}", int(r.choice([80, 443, 443, 443, 53, 22]))
        src = ATTACKERS[label][r.integers(len(ATTACKERS[label]))]
        dst = "203.0.113.250" if label in ("botnet", "exfil") else f"10.0.9.{r.integers(1, 4)}"
        ports = PORTS[label]
        return src, dst, int(r.integers(1, 10000)) if ports is None else int(ports[r.integers(len(ports))])

    @staticmethod
    def _detail(atype, row, dist, thr):
        if atype == "dos":
            return f"{int(row['count'])} connections/2s, SYN-error rate {row['serror_rate']:.0%}, {row['pkt_rate']:.0f} pkt/s"
        if atype == "probe":
            return f"{int(row['unique_urls'])} distinct URLs, {int(row['dst_host_count'])} hosts touched, {row['status_4xx_rate']:.0%} 4xx"
        if atype == "brute_force":
            return f"{int(row['failed_logins'])} failed logins, {row['status_4xx_rate']:.0%} 401/403 responses"
        if atype == "exfil":
            return f"{row['bandwidth_kbps']:,.0f} kbit/s, {(row['src_bytes'] + row['dst_bytes']) / 1e6:.1f} MB in one session"
        if atype == "sqli":
            return f"{int(row['n_sql_kw'])} SQL keywords, {int(row['n_special'])} special chars in the request"
        return f"K-Means distance {dist:.1f} is above the normal limit {thr:.1f}; no known signature"

    def _ingest(self, flows, scored):
        preds, conf, dist, rf_conf = scored
        out = []
        for i, (idx, row) in enumerate(flows.iterrows()):
            truth = row["label"]
            src, dst, port = self._endpoint(truth)
            attack = truth != "normal"
            ev = dict(kind="flow", id=0, t=self.clock.strftime("%H:%M:%S"), src=src, dst=dst, port=port,
                      proto=PROTOCOLS[int(row["protocol"])], bytes=int(row["src_bytes"] + row["dst_bytes"]),
                      kbps=round(float(row["bandwidth_kbps"]), 1), request=row["request"], truth=truth,
                      conf=round(float(conf[i]), 2), dist=round(float(dist[i]), 2), verdict="ok", type="normal",
                      sev="", mitre="", by="", detail="")
            if src in self.blocked:
                ev.update(verdict="dropped", type=self.blocked[src]["type"], sev=INTEL[self.blocked[src]["type"]][0], by="firewall")
            else:
                strange = dist[i] > self.thr
                atype = preds[i] if preds[i] != "normal" else ("unknown" if strange else None)
                if atype and atype != "unknown" and strange and rf_conf[i] < UNKNOWN_CONF:
                    atype = "unknown"                       # the forest is unsure AND the flow is far from normal
                if atype:
                    sev, mid, mname = INTEL[atype]
                    by = "ensemble + k-means" if preds[i] != "normal" and strange else ("ensemble" if preds[i] != "normal" else "k-means")
                    ev.update(verdict="alert", type=atype, sev=sev, mitre=f"{mid} {mname}", by=by,
                              detail=self._detail(atype, row, float(dist[i]), self.thr))
            ev["id"] = self._push(ev)
            self.stat["flows"] += 1
            if ev["verdict"] != "ok":
                self.history.append(dict(ev, ts=self.clock))
                self.stat["alerts" if ev["verdict"] == "alert" else "dropped"] += 1
                self.by_type[ev["type"]] += 1
                self.by_src[src] += 1
                if ev["verdict"] == "alert":
                    self.alerts.appendleft(ev)
                    if ev["type"] == "sqli" and row["request"]:
                        self.sqli.appendleft(ev)
                    self.src_alerts[src] += 1
                    if self.src_alerts[src] >= BLOCK_AFTER and src not in self.blocked:
                        self.blocked[src] = dict(since=self.clock, type=ev["type"], at=ev["t"])
                        fw = dict(kind="fw", t=ev["t"], msg=f"FIREWALL: blocked {src} after {BLOCK_AFTER} {ev['type'].upper()} alerts")
                        self._push(fw)
                        self.fw_log.append(dict(ts=self.clock, msg=fw["msg"]))
                        out.append(fw)
            self.stat[("tp" if ev["verdict"] != "ok" else "fn") if attack else ("fp" if ev["verdict"] != "ok" else "tn")] += 1
            self._bucket_add(ev)
            out.append(ev)
        return out

    def _push(self, ev):
        self.eid += 1
        ev["id"] = self.eid
        self.events.append(ev)
        return self.eid

    def _expire(self):
        out = []
        for ip in [ip for ip, b in self.blocked.items() if (self.clock - b["since"]).total_seconds() > BLOCK_TTL]:
            del self.blocked[ip]
            self.src_alerts[ip] = 0
            fw = dict(kind="fw", t=self.clock.strftime("%H:%M:%S"), msg=f"FIREWALL: block on {ip} expired")
            self._push(fw)
            self.fw_log.append(dict(ts=self.clock, msg=fw["msg"]))
            out.append(fw)
        return out

    # ------------------------------------------------------------------ per-second series
    def _bucket_add(self, ev):
        if self.bucket is None:
            self.bucket = self._new_bucket(ev["t"])
        b = self.bucket
        b["bytes"] += ev["bytes"]
        b["flows"] += 1
        b["alerts"] += ev["verdict"] != "ok"
        b["dropped"] += ev["verdict"] == "dropped"
        attack, flagged = ev["truth"] != "normal", ev["verdict"] != "ok"
        b["tp" if attack and flagged else "fn" if attack else "fp" if flagged else "tn"] += 1
        b[ev["proto"]] += 1
        b["tt"][f"{ev['truth']}|{int(flagged)}"] += 1                       # flows per ground-truth class, caught or not

    def _new_bucket(self, t):
        return dict(t=t, ts=self.clock, bytes=0, flows=0, alerts=0, dropped=0, tp=0, fn=0, fp=0, tn=0, tcp=0, udp=0, icmp=0, tt=Counter())

    def _tick_series(self, out):
        if self.clock.microsecond == 0 or self.clock.second != (self.clock - timedelta(seconds=TICK)).second:
            b = self.bucket or self._new_bucket(self.clock.strftime("%H:%M:%S"))
            p = dict(t=b["t"], mbps=round(b["bytes"] * 8 / 1e6, 3), flows=b["flows"], alerts=b["alerts"])
            self.series.append(p)
            self.hist_series.append(dict(p, ts=b["ts"], tt=dict(b["tt"]), **{k: b[k] for k in ("dropped", "tp", "fn", "fp", "tn", "tcp", "udp", "icmp")}))
            self.bucket = None

    # ------------------------------------------------------------------ data for the attack report
    def report_data(self, minutes=None):
        """Everything the PDF report needs for the last `minutes` of simulated time (None = since the start)."""
        with self.lock:
            end = self.clock
            start = max(self.start_clock, end - timedelta(minutes=minutes)) if minutes else self.start_clock
            ph = [p for p in self.phase_log if p["ts"] <= end]
            first = max([i for i, p in enumerate(ph) if p["ts"] <= start], default=0)
            return dict(start=start, end=end,
                        events=[e for e in self.history if start <= e["ts"] <= end],
                        series=[p for p in self.hist_series if start <= p["ts"] <= end],
                        firewall=[m for m in self.fw_log if start <= m["ts"] <= end],
                        phases=ph[first:],
                        meta=dict(rate=self.base_rate, auto=self.auto, level=self.level, threshold=float(self.thr),
                                  models=self.model_meta.get("models", {}), zero_day=self.model_meta.get("zero_day", {})))

    # ------------------------------------------------------------------ view for the dashboard
    def state(self, since=0):
        with self.lock:
            s = self.stat
            att, norm = s["tp"] + s["fn"], s["fp"] + s["tn"]
            recent = sum(p["alerts"] for p in list(self.series)[-10:])
            threat = "LOW" if recent < 4 else "ELEVATED" if recent < 25 else "HIGH" if recent < 70 else "CRITICAL"
            ph = self.cur or dict(title=IDLE[0], left=0, key="idle")
            return dict(
                now=self.clock.strftime("%H:%M:%S"), threat=threat, paused=self.paused, recent_alerts=recent,
                phase=dict(key=ph["key"], title=ph["title"], seconds_left=None if ph["key"] == "idle" else round(ph["left"] * TICK)),
                queue=[q[0] for q in self.queue],
                timer=dict(active=bool(self.run_until), finished=self.finished,
                           until=self.run_until.strftime("%H:%M:%S") if self.run_until else None,
                           left=max(0, int((self.run_until - self.clock).total_seconds())) if self.run_until else 0), auto=self.auto, level=self.level, rate=self.base_rate,
                kpi=dict(flows=s["flows"], alerts=s["alerts"], dropped=s["dropped"], blocked=len(self.blocked),
                         detection=round(s["tp"] / att, 3) if att else None, false_alarm=round(s["fp"] / norm, 4) if norm else None,
                         attacks=att, mbps=self.series[-1]["mbps"] if self.series else 0),
                series=list(self.series), by_type=dict(self.by_type),
                events=[e for e in self.events if e["id"] > since][-250:],
                alerts=list(self.alerts)[:40], sqli=list(self.sqli)[:12],
                blocked=[dict(ip=ip, type=b["type"], at=b["at"], left=max(0, round(BLOCK_TTL - (self.clock - b["since"]).total_seconds())))
                         for ip, b in self.blocked.items()],
                top=[dict(ip=ip, n=n) for ip, n in self.by_src.most_common(6)],
                last_id=self.eid)
