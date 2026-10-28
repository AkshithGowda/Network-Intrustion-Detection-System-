"""Synthetic traffic generator: network flows + web access-log lines (a stand-in for KDD-style records).

Every record combines three kinds of evidence a real IDS would see:
  * bandwidth / flow statistics  (bytes, kbps, packet rate, connection counts, SYN errors)
  * access-log behaviour         (visits per minute, distinct URLs, 4xx share, failed logins)
  * the HTTP request text        (parsed into SQL-injection indicators by `request_features`)

Six classes are learned. `botnet` (quiet, regular beaconing) is never shown to the supervised models and
plays the role of an unknown "zero-day" attack. The same generator feeds training and the live simulation.
"""
import re
from urllib.parse import quote_plus, unquote_plus

import numpy as np
import pandas as pd

CLASSES = ["normal", "dos", "probe", "brute_force", "sqli", "exfil"]
ZERO_DAY = "botnet"
PROTOCOLS = ["tcp", "udp", "icmp"]
FLOW = ["duration", "protocol", "src_bytes", "dst_bytes", "bandwidth_kbps", "pkt_rate", "count", "srv_count",
        "serror_rate", "rerror_rate", "same_srv_rate", "diff_srv_rate", "dst_host_count"]
ACCESS = ["req_per_min", "unique_urls", "status_4xx_rate", "failed_logins", "logged_in"]
PAYLOAD = ["url_len", "n_special", "n_sql_kw", "pct_enc"]
FEATURES = FLOW + ACCESS + PAYLOAD
LOG_COLS = ["duration", "src_bytes", "dst_bytes", "bandwidth_kbps", "pkt_rate", "count", "srv_count", "dst_host_count",
            "req_per_min", "unique_urls", "url_len", "n_special", "n_sql_kw"]
TRAIN_MIX = {"normal": .55, "dos": .14, "probe": .10, "brute_force": .07, "sqli": .08, "exfil": .06}

# ----------------------------------------------------------------------------- request text -> features
_SQL_KW = re.compile(r"\b(union|select|drop|insert|delete|sleep|benchmark|information_schema|load_file|xp_cmdshell)\b")
_SQL_BOOL = re.compile(r"\b(or|and)\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+")
_SPECIAL = set("'\";()<>#")


def request_features(req: str) -> dict:
    """SQL-injection indicators of one HTTP request line (all zero for flows without a request)."""
    if not req:
        return dict(url_len=0, n_special=0, n_sql_kw=0, pct_enc=0.0)
    dec = unquote_plus(req).lower()
    return dict(url_len=len(req),
                n_special=sum(c in _SPECIAL for c in dec) + dec.count("--"),
                n_sql_kw=len(_SQL_KW.findall(dec)) + len(_SQL_BOOL.findall(dec)),
                pct_enc=req.count("%") * 3 / len(req))


_WORDS = ["temple", "seva", "timings", "festival", "donation", "parking", "darshan", "prasada", "contact", "map"]
_BENIGN_TRAPS = ["/search?q=o'brien", "/search?q=select+seva+type", "/search?q=drop+off+time", "/search?q=rice+and+curry",
                 "/news?cat=events;festival"]
_SQLI = ["' OR '1'='1", "' OR 1=1--", "1 UNION SELECT username,password FROM users--", "1; DROP TABLE users;--",
         "1' AND SLEEP(5)--", "admin'--", "1 UNION SELECT NULL,table_name FROM information_schema.tables--",
         "' OR 'x'='x", "1 AND 1=1", "1) OR (1=1", "1'", "1 ORDER BY 5--"]
_SCAN = ["/admin", "/.env", "/phpmyadmin", "/wp-login.php", "/backup.zip", "/.git/config", "/config.php", "/server-status"]
_EXFIL = ["/backup/db_dump.sql", "/download?file=customers.csv", "/export/all_users.zip", "/backup/site_full.tar.gz"]


def _pick(rng, items):
    return items[rng.integers(len(items))]


def _request(kind, rng) -> str:
    if kind == "normal":
        if rng.random() < .06:
            return "GET " + _pick(rng, _BENIGN_TRAPS)
        r = rng.random()
        if r < .25:
            return "GET /"
        if r < .5:
            return f"GET /products?id={rng.integers(1, 900)}"
        if r < .7:
            return f"GET /search?q={_pick(rng, _WORDS)}+{_pick(rng, _WORDS)}"
        if r < .85:
            return f"GET /news?cat={_pick(rng, _WORDS)}"
        return f"POST /login?user=u{rng.integers(1, 500)}"
    if kind == "dos":
        return f"GET /?x={rng.integers(0, 10**6)}" if rng.random() < .5 else ""
    if kind == "probe":
        return "GET " + _pick(rng, _SCAN) if rng.random() < .6 else ""
    if kind == "brute_force":
        return f"POST /login?user=admin&pass={rng.integers(10**4, 10**8):x}"
    if kind == "sqli":
        payload = _pick(rng, _SQLI)
        if rng.random() < .3:
            payload = quote_plus(payload)
        return f"GET /{_pick(rng, ['products?id=', 'search?q=', 'news?cat=', 'login?user='])}{payload}"
    if kind == "exfil":
        return "GET " + _pick(rng, _EXFIL)
    return f"POST /api/beacon?id={rng.integers(0, 16**6):06x}"      # botnet


# ----------------------------------------------------------------------------- flow + access-log statistics
def _ln(rng, mu, sd, n):
    return rng.lognormal(mu, sd, n)


def _pois(rng, lam, n, lo=0):
    return np.clip(rng.poisson(lam, n), lo, 511)


def _normal_flow(rng, n, busy=True):
    d = _plain_flow(rng, n)
    if busy:                                # legitimate look-alikes: flash crowds (festival day) and big downloads
        crowd, big = rng.random(n) < .07, rng.random(n) < .04
        d["req_per_min"] = np.where(crowd, _ln(rng, 4, .6, n), d["req_per_min"])
        d["count"] = np.where(crowd, _pois(rng, 60, n, 1), d["count"])
        d["pkt_rate"] = np.where(crowd, _ln(rng, 4, .7, n), d["pkt_rate"])
        d["unique_urls"] = np.where(crowd, _pois(rng, 8, n, 1), d["unique_urls"])
        d["status_4xx_rate"] = np.where(crowd, rng.beta(2, 15, n), d["status_4xx_rate"])
        d["dst_bytes"] = np.where(big, _ln(rng, 12, 1.2, n), d["dst_bytes"])
        d["failed_logins"] = d["failed_logins"] + (rng.random(n) < .03) * rng.integers(1, 4, n)   # forgotten passwords
    return d


def _plain_flow(rng, n):
    return dict(duration=_ln(rng, -.3, 1.3, n), protocol=rng.choice(3, n, p=[.75, .2, .05]), src_bytes=_ln(rng, 6, 1.6, n),
                dst_bytes=_ln(rng, 7, 1.8, n), count=_pois(rng, 8, n, 1), srv_count=_pois(rng, 6, n, 1),
                serror_rate=rng.beta(1, 30, n), rerror_rate=rng.beta(1, 30, n), same_srv_rate=rng.beta(8, 1.5, n),
                diff_srv_rate=rng.beta(1, 15, n), dst_host_count=np.clip(rng.gamma(2, 15, n), 1, 255).astype(int),
                pkt_rate=_ln(rng, 2, .8, n), req_per_min=_ln(rng, 1.8, .8, n), unique_urls=_pois(rng, 3, n, 1),
                status_4xx_rate=rng.beta(1, 25, n), failed_logins=rng.poisson(.03, n), logged_in=rng.binomial(1, .8, n))


def _gen(kind, n, rng):
    """Flow/access columns for n records of one kind. Distributions overlap on purpose (accuracy < 100 %)."""
    d = _normal_flow(rng, n, busy=kind == "normal")
    if kind in ("normal", "sqli"):          # SQL injection looks like ordinary traffic at flow level: only the payload gives it away
        if kind == "sqli":
            d["req_per_min"] = _ln(rng, 2.4, .6, n)
            d["status_4xx_rate"] = rng.beta(2, 12, n)
        return d
    if kind == "dos":                       # SYN / ICMP flood; 15 % are slow "stealthy" floods that look closer to normal
        slow = rng.random(n) < .15
        count = np.where(slow, _pois(rng, 40, n), _pois(rng, 250, n))
        d.update(duration=_ln(rng, -4, 1, n), protocol=rng.choice(3, n, p=[.6, .05, .35]), src_bytes=_ln(rng, 3.5, 1.2, n),
                 dst_bytes=_ln(rng, 0, 1, n), count=count, srv_count=np.clip(count * rng.uniform(.8, 1, n), 1, 511).astype(int),
                 serror_rate=np.where(slow, rng.beta(2, 6, n), rng.beta(15, 1.5, n)), same_srv_rate=rng.beta(20, 1, n),
                 diff_srv_rate=rng.beta(1, 30, n), dst_host_count=rng.integers(1, 30, n),
                 pkt_rate=np.where(slow, _ln(rng, 4.2, .6, n), _ln(rng, 6, .7, n)), req_per_min=_ln(rng, 5.5, .7, n),
                 unique_urls=_pois(rng, 1, n, 1), logged_in=np.zeros(n, int), failed_logins=np.zeros(n, int))
    elif kind == "probe":                   # port / path scan: many services, many hosts, many resets and 404s
        d.update(duration=_ln(rng, -3, 1, n), src_bytes=_ln(rng, 3.5, 1, n), dst_bytes=_ln(rng, 3, 1.2, n),
                 count=_pois(rng, 30, n, 1), srv_count=_pois(rng, 3, n, 1), serror_rate=rng.beta(4, 4, n),
                 rerror_rate=rng.beta(5, 3, n), same_srv_rate=rng.beta(1.5, 8, n), diff_srv_rate=rng.beta(8, 2, n),
                 dst_host_count=rng.integers(100, 256, n), pkt_rate=_ln(rng, 3.5, .8, n), req_per_min=_ln(rng, 3.5, .6, n),
                 unique_urls=_pois(rng, 25, n, 5), status_4xx_rate=rng.beta(8, 2, n), logged_in=np.zeros(n, int),
                 failed_logins=np.zeros(n, int))
    elif kind == "brute_force":             # password guessing: repeated failed logins, 401/403 responses
        d.update(duration=_ln(rng, 2.5, .6, n), protocol=np.zeros(n, int), src_bytes=_ln(rng, 5.5, .5, n),
                 dst_bytes=_ln(rng, 5, .5, n), count=_pois(rng, 15, n, 1), srv_count=_pois(rng, 14, n, 1),
                 rerror_rate=rng.beta(2, 8, n), same_srv_rate=rng.beta(9, 1, n), pkt_rate=_ln(rng, 2.5, .6, n),
                 req_per_min=_ln(rng, 3.2, .4, n), unique_urls=_pois(rng, 1, n, 1), status_4xx_rate=rng.beta(8, 3, n),
                 failed_logins=rng.poisson(3.5, n), logged_in=rng.binomial(1, .15, n))
    elif kind == "exfil":                   # bandwidth abuse: very large transfers from a logged-in session
        d.update(duration=_ln(rng, 2.5, .8, n), protocol=np.zeros(n, int), src_bytes=_ln(rng, 8, 1, n),
                 dst_bytes=_ln(rng, 14, 1, n), count=_pois(rng, 3, n, 1), srv_count=_pois(rng, 3, n, 1),
                 pkt_rate=_ln(rng, 5, .6, n), req_per_min=_ln(rng, 1.2, .5, n), unique_urls=_pois(rng, 2, n, 1),
                 logged_in=np.ones(n, int))
    else:                                   # botnet beaconing: tiny, regular, unusual service pattern
        d.update(duration=_ln(rng, 1, .3, n), protocol=rng.choice(3, n, p=[.5, .5, 0]), src_bytes=_ln(rng, 4.2, .3, n),
                 dst_bytes=_ln(rng, 4.5, .3, n), count=_pois(rng, 3, n, 1), srv_count=_pois(rng, 2, n, 1),
                 serror_rate=rng.beta(1, 40, n), rerror_rate=rng.beta(1, 40, n), same_srv_rate=rng.beta(2, 6, n),
                 diff_srv_rate=rng.beta(6, 3, n), dst_host_count=rng.integers(1, 10, n), pkt_rate=_ln(rng, .6, .3, n),
                 req_per_min=_ln(rng, .5, .3, n), unique_urls=np.ones(n, int), status_4xx_rate=rng.beta(1, 60, n),
                 logged_in=np.ones(n, int), failed_logins=np.zeros(n, int))
    stealth = {"dos": .12, "probe": .20, "brute_force": .22, "exfil": .20, ZERO_DAY: 0}[kind]
    if stealth:                             # low-and-slow variants: part of the record looks like ordinary traffic
        base = _normal_flow(rng, n, busy=False)
        mask = rng.random(n) < stealth
        for c in d:
            d[c] = np.where(mask & (rng.random(n) < .55), base[c], d[c])
    return d


def make_flows(n, mix, rng):
    """n random records whose class frequencies follow `mix` (kind -> weight). Columns: FEATURES + request + label."""
    kinds = rng.choice(list(mix), n, p=np.array(list(mix.values()), float) / sum(mix.values()))
    parts = []
    for k in sorted(set(kinds)):
        idx = np.where(kinds == k)[0]
        df = pd.DataFrame(_gen(k, len(idx), rng), index=idx)
        df["request"] = [_request(k, rng) for _ in idx]
        df["label"] = k
        parts.append(df)
    df = pd.concat(parts).sort_index()
    df["bandwidth_kbps"] = (df["src_bytes"] + df["dst_bytes"]) * 8 / 1000 / df["duration"].clip(lower=.001)
    df = pd.concat([df, pd.DataFrame([request_features(r) for r in df["request"]], index=df.index)], axis=1)
    return df[FEATURES + ["request", "label"]]


def log_scale(X):
    """Heavy-tailed columns -> log scale, so K-Means distances are not dominated by byte counts."""
    X = X[FEATURES].copy()
    X[LOG_COLS] = np.log1p(X[LOG_COLS])
    return X
