"""Attack report (PDF, 9 pages or more) for a chosen time window, built from the engine's history.

    from report import build_report;  pdf_bytes, pages = build_report(engine.report_data(minutes=15))

Pages: 1 summary, 2 timeline, 3 attack breakdown, 4 traffic statistics, 5 detection performance, 6 offenders and response,
7 SQL injection and bandwidth, 8 recommendations and settings, then the full alert log.
"""
import io
import textwrap
from collections import Counter, defaultdict
from datetime import datetime

import matplotlib
import matplotlib.dates as mdates
import numpy as np
from matplotlib.backends.backend_pdf import PdfPages

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

A4 = (8.27, 11.69)
INK, MUTE, LINE = "#14171c", "#5b6472", "#c9ced6"
TYPE_COL = {"dos": "#d6303f", "probe": "#c98a10", "brute_force": "#d9702a", "sqli": "#9c4fc4", "exfil": "#2b8fd0", "unknown": "#444b57"}
NAME = {"dos": "DoS flood", "probe": "Port / path scan", "brute_force": "Brute force", "sqli": "SQL injection", "exfil": "Data exfiltration",
        "unknown": "Unknown (zero-day)"}
SHORT = {"dos": "DoS", "probe": "Scan", "brute_force": "Brute force", "sqli": "SQLi", "exfil": "Exfiltration", "unknown": "Unknown"}
TRUTH = {"normal": "Normal traffic", "dos": "DoS flood", "probe": "Port / path scan", "brute_force": "Brute force", "sqli": "SQL injection",
         "exfil": "Data exfiltration", "botnet": "Botnet beaconing (unseen)"}
EXPECT = {"dos": "dos", "probe": "probe", "brute_force": "brute_force", "sqli": "sqli", "exfil": "exfil", "botnet": "unknown"}
ADVICE = {
    "dos": "Rate-limit and SYN-cookie the exposed service, put a CDN or scrubbing service in front, and keep an upstream block-list ready.",
    "probe": "Close unused ports, hide admin and backup paths, and alert on bursts of 404 and reset responses from one source.",
    "brute_force": "Lock accounts after repeated failures, require multi-factor login, add per-source rate limits and CAPTCHA on the login page.",
    "sqli": "Fix the cause in code: parameterised queries and input validation. Add a web application firewall as a second layer and review the targeted endpoints.",
    "exfil": "Restrict who can reach backup and export paths, apply egress filtering and data-loss rules, and investigate the internal host that moved the data.",
    "unknown": "Treat as a possible command-and-control channel: isolate the internal hosts, inspect their processes and DNS, and add the pattern to the signature set.",
}


def _clip(s, n):
    s = str(s)
    return s if len(s) <= n else s[: n - 1] + "…"


def _hms(ts):
    return ts.strftime("%H:%M:%S") if isinstance(ts, datetime) else str(ts)


def _pct(a, b, digits=1):
    return f"{a / b:.{digits}%}" if b else "n/a"


class Doc:
    def __init__(self, title, window):
        self.pages, self.title, self.window = [], title, window

    def page(self, heading):
        fig = plt.figure(figsize=A4)
        fig.patch.set_facecolor("white")
        fig.text(0.07, 0.965, self.title, fontsize=8, color=MUTE)
        fig.text(0.93, 0.965, self.window, fontsize=8, color=MUTE, ha="right")
        fig.add_artist(plt.Line2D([0.07, 0.93], [0.955, 0.955], color=LINE, lw=.8))
        fig.text(0.07, 0.915, heading, fontsize=16, fontweight="bold", color=INK)
        self.pages.append(fig)
        return fig, 0.885

    def text(self, fig, y, s, size=9.5, weight="normal", color=INK, wrap=104, x=0.07, gap=0.0165, indent=""):
        for line in textwrap.wrap(s, wrap) or [""]:
            fig.text(x, y, indent + line, fontsize=size, fontweight=weight, color=color, va="top")
            y -= gap * size / 9.5
            indent = " " * len(indent)
        return y - 0.004

    def sub(self, fig, y, s):
        fig.text(0.07, y, s, fontsize=11, fontweight="bold", color=INK, va="top")
        return y - 0.028

    def bullets(self, fig, y, items, **kw):
        for it in items:
            y = self.text(fig, y, it, indent="•  ", wrap=100, **kw)
        return y

    def table(self, fig, y, header, rows, widths, size=8, rh=0.0215, x=0.07, w=0.86):
        n = len(rows) + 1
        h = rh * n
        ax = fig.add_axes([x, y - h, w, h])
        ax.axis("off")
        tb = ax.table(cellText=[list(map(str, r)) for r in rows] or [[""] * len(header)], colLabels=header, colWidths=widths, bbox=[0, 0, 1, 1], cellLoc="left")
        tb.auto_set_font_size(False)
        tb.set_fontsize(size)
        for (r, c), cell in tb.get_celld().items():
            cell.set_edgecolor(LINE)
            cell.set_linewidth(.6)
            cell.PAD = .03
            if r == 0:
                cell.set_facecolor("#eef0f3")
                cell.set_text_props(fontweight="bold", color=INK)
            else:
                cell.set_text_props(color=INK)
        return y - h - 0.02

    def save(self, previews=None):
        """previews: optional {page number: png path}, used to show sample pages in the project report."""
        buf = io.BytesIO()
        with PdfPages(buf) as pdf:
            n = len(self.pages)
            for i, fig in enumerate(self.pages, 1):
                fig.text(0.5, 0.025, f"Page {i} of {n}", fontsize=8, color=MUTE, ha="center")
                pdf.savefig(fig)
                if previews and i in previews:
                    fig.savefig(previews[i], dpi=110)
                plt.close(fig)
        return buf.getvalue(), len(self.pages)


def _axes(fig, rect, ylabel="", title=""):
    ax = fig.add_axes(rect)
    ax.set_ylabel(ylabel, fontsize=8)
    ax.set_title(title, fontsize=9, loc="left", color=INK)
    ax.tick_params(labelsize=7)
    ax.grid(alpha=.25, lw=.5)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    return ax


def build_report(d, previews=None):
    """d is Engine.report_data(): window, per-second series, attack history, firewall log, phase log and settings."""
    ev, ser, fw, phases, meta = d["events"], d["series"], d["firewall"], d["phases"], d.get("meta", {})
    start, end = d["start"], d["end"]
    secs = max(1.0, (end - start).total_seconds())
    mins = secs / 60
    doc = Doc("Network Intrusion Report - Sentinel NIDS", f"{_hms(start)} to {_hms(end)}  ({mins:.1f} min)")

    # ---------------------------------------------------------------- numbers used on several pages
    alerts = [e for e in ev if e["verdict"] == "alert"]
    dropped = [e for e in ev if e["verdict"] == "dropped"]
    by_type = Counter(e["type"] for e in ev)
    flows = sum(p["flows"] for p in ser)
    tp, fn, fp, tn = (sum(p[k] for p in ser) for k in ("tp", "fn", "fp", "tn"))
    attack_flows = tp + fn
    bw = [p["mbps"] for p in ser]
    total_mb = sum(bw) / 8
    avg_bw = float(np.mean(bw)) if bw else 0.0
    p95_bw = float(np.percentile(bw, 95)) if bw else 0.0
    peak_bw = max(ser, key=lambda p: p["mbps"], default=None)
    peak_al = max(ser, key=lambda p: p["alerts"], default=None)
    peak_fl = max(ser, key=lambda p: p["flows"], default=None)
    proto = {k: sum(p.get(k, 0) for p in ser) for k in ("tcp", "udp", "icmp")}
    tt = Counter()
    for p in ser:
        tt.update(p.get("tt", {}))
    precision, recall = (tp / (tp + fp) if tp + fp else None), (tp / (tp + fn) if tp + fn else None)
    f1 = 2 * precision * recall / (precision + recall) if precision and recall else None
    by_src = defaultdict(list)
    for e in ev:
        by_src[e["src"]].append(e)
    first_seen = {ip: min(i["ts"] for i in it) for ip, it in by_src.items()}
    blocks = [m for m in fw if "blocked" in m["msg"]]
    ttb = []
    for m in blocks:
        ip = m["msg"].split("blocked ")[1].split(" ")[0]
        if ip in first_seen:
            ttb.append(max(0.0, (m["ts"] - first_seen[ip]).total_seconds()))
    dets = Counter(e["by"] for e in alerts)
    fa_ev = [e for e in alerts if e["truth"] == "normal"]

    # ================================================================ 1. summary
    fig, y = doc.page("1. Executive summary")
    y = doc.text(fig, y, f"This report covers the traffic seen by the sensor from {_hms(start)} to {_hms(end)} ({mins:.1f} minutes of simulated traffic). "
                         "Alerts come from a supervised ensemble (decision tree, bagging, AdaBoost, random forest) and a K-Means anomaly detector trained on normal traffic. "
                         "Detection figures are measured against the simulation's ground truth.")
    y = doc.table(fig, y - .01, ["Measure", "Value"], [
        ["Flows analysed", f"{flows:,} ({flows / secs:.1f} per second on average)"], ["Attack flows in the traffic (ground truth)", f"{attack_flows:,} ({_pct(attack_flows, flows)})"],
        ["Alerts raised / flows dropped by the firewall", f"{len(alerts):,} / {len(dropped):,}"],
        ["Attack types seen", _clip(", ".join(SHORT[t] for t in by_type) or "none", 52)], ["Sources blocked", f"{len(blocks)}"],
        ["Precision / recall (detection rate)", f"{_pct(tp, tp + fp)} / {_pct(tp, tp + fn)}"], ["False-alarm rate", _pct(fp, fp + tn, 2)],
        ["Data transferred / average bandwidth", f"{total_mb:,.1f} MB / {avg_bw:.2f} Mbit/s"],
        ["Peak bandwidth", f"{peak_bw['mbps']:.2f} Mbit/s at {_hms(peak_bw['ts'])}" if peak_bw else "n/a"],
        ["Peak alert rate", f"{peak_al['alerts']} alerts/s at {_hms(peak_al['ts'])}" if peak_al else "n/a"],
        ["Median time from first alert to block", f"{np.median(ttb):.1f} s" if ttb else "n/a"],
    ], [0.5, 0.5], size=8.5)
    y = doc.sub(fig, y, "Key findings")
    finds = []
    if by_type:
        t, c = by_type.most_common(1)[0]
        finds.append(f"{len(ev)} attack events (alerts plus dropped flows) in {len(by_type)} categories. The most frequent was {NAME[t]} with {c} events ({c / len(ev):.0%}).")
        ip, items = max(by_src.items(), key=lambda kv: len(kv[1]))
        finds.append(f"The most active source was {ip} with {len(items)} events, mainly {NAME[Counter(i['type'] for i in items).most_common(1)[0][0]]}.")
    else:
        finds.append("No attack events were recorded in this window. Only normal traffic was seen.")
    if peak_bw and peak_bw["mbps"] > 5:
        finds.append(f"A bandwidth spike of {peak_bw['mbps']:.1f} Mbit/s at {_hms(peak_bw['ts'])} is far above the normal level; check for data exfiltration.")
    if by_type.get("unknown"):
        finds.append(f"{by_type['unknown']} events were flagged as unknown. No signature matched, but they are far from normal behaviour (possible zero-day or command-and-control traffic).")
    if blocks:
        finds.append(f"The firewall blocked {len(blocks)} source(s) after repeated alerts and dropped {len(dropped)} later flows from them ({_pct(len(dropped), attack_flows)} of all attack flows).")
    finds.append(f"{fp} normal flows were flagged by mistake (false alarms); this is the price of the anomaly detector and should be reviewed by an analyst.")
    seen = [p["title"] for p in phases if p["key"] not in ("idle", "normal")]
    if seen:
        finds.append("Scenarios in the window: " + "; ".join(dict.fromkeys(seen)) + ".")
    doc.bullets(fig, y, finds)

    # ================================================================ 2. timeline
    fig, y = doc.page("2. Timeline")
    doc.text(fig, y, "Bandwidth, flow rate and alert rate for every second in the window. Shaded bands mark the scenario that was running.", wrap=104)
    xs = [p["ts"] for p in ser]
    fmt = mdates.DateFormatter("%H:%M:%S")
    a1 = _axes(fig, [0.1, 0.62, 0.84, 0.2], "Mbit/s", "Bandwidth")
    a2 = _axes(fig, [0.1, 0.37, 0.84, 0.2], "per second", "Flows (grey) and alerts (red)")
    a3 = _axes(fig, [0.1, 0.1, 0.84, 0.21], "events / 10 s", "Attack events by type")
    for a in (a1, a2, a3):
        a.xaxis.set_major_formatter(fmt)
    if xs:
        a1.fill_between(xs, bw, color="#8a93a3", alpha=.35)
        a1.plot(xs, bw, color="#4a5260", lw=1)
        a2.plot(xs, [p["flows"] for p in ser], color="#8a93a3", lw=1)
        a2.plot(xs, [p["alerts"] for p in ser], color="#d6303f", lw=1.2)
        for i, p in enumerate(phases):
            if p["key"] in ("idle", "normal"):
                continue
            t1 = phases[i + 1]["ts"] if i + 1 < len(phases) else end
            for a in (a1, a2):
                a.axvspan(max(p["ts"], start), min(t1, end), color=TYPE_COL.get(p["key"], "#9aa3b2"), alpha=.08)
            a1.text(max(p["ts"], start), a1.get_ylim()[1], _clip(p["title"], 22), fontsize=6, rotation=90, va="top", color=MUTE)
        bins = defaultdict(Counter)
        for e in ev:
            bins[int(e["ts"].timestamp() // 10)][e["type"]] += 1
        bx = sorted(bins)
        bottoms = [0] * len(bx)
        for t in NAME:
            vals = [bins[b][t] for b in bx]
            if any(vals):
                a3.bar([datetime.fromtimestamp(b * 10) for b in bx], vals, width=9 / 86400, bottom=bottoms, color=TYPE_COL[t], label=NAME[t])
                bottoms = [a + b for a, b in zip(bottoms, vals)]
        if by_type:
            a3.legend(fontsize=6.5, ncol=3, frameon=False, loc="upper left")
        for a in (a1, a2, a3):
            a.set_xlim(start, end)
    else:
        a1.text(.5, .5, "no traffic in this window", transform=a1.transAxes, ha="center", color=MUTE)

    # ================================================================ 3. attack breakdown
    fig, y = doc.page("3. Attack breakdown")
    y = doc.text(fig, y, "Events per attack type with the MITRE ATT&CK technique the type maps to. Dropped flows are later flows from sources the firewall had already blocked.")
    rows = []
    for t, c in by_type.most_common():
        items = [e for e in ev if e["type"] == t]
        rows.append([NAME[t], items[0]["mitre"].split(" ")[0], items[0]["sev"], c, sum(e["verdict"] == "dropped" for e in items),
                     len({e["src"] for e in items}), _hms(min(e["ts"] for e in items)), _hms(max(e["ts"] for e in items))])
    if by_type:
        ax = fig.add_axes([0.3, y - 0.22, 0.6, 0.2])
        ts = [t for t, _ in by_type.most_common()][::-1]
        ax.barh([NAME[t] for t in ts], [by_type[t] for t in ts], color=[TYPE_COL[t] for t in ts])
        ax.tick_params(labelsize=8)
        for s in ("top", "right"):
            ax.spines[s].set_visible(False)
        for i, t in enumerate(ts):
            ax.text(by_type[t], i, f" {by_type[t]}", va="center", fontsize=8)
        y -= .26
    y = doc.table(fig, y, ["Type", "MITRE", "Severity", "Events", "Dropped", "Sources", "First seen", "Last seen"], rows, [.2, .1, .11, .09, .1, .1, .15, .15])
    if by_type:
        y = doc.sub(fig, y, "What each type means")
        meaning = {"dos": "Very many connections or packets per second with a high SYN-error rate.", "probe": "Many distinct URLs or hosts touched, many 404 and reset replies.",
                   "brute_force": "Repeated failed logins and 401/403 replies on the login path.", "sqli": "SQL keywords or quotes inside a web request, sometimes URL-encoded.",
                   "exfil": "A very large transfer from a logged-in internal host.", "unknown": "Far from normal traffic, but no known attack pattern matched."}
        doc.bullets(fig, y, [f"{NAME[t]}: {meaning[t]}" for t in by_type], size=9)

    # ================================================================ 4. traffic statistics
    fig, y = doc.page("4. Traffic statistics")
    y = doc.text(fig, y, "Volume, bandwidth and protocol mix of all traffic in the window, normal and malicious, plus a minute-by-minute view.")
    pk = lambda p: _hms(p["ts"]) if p else "n/a"  # noqa: E731
    y = doc.table(fig, y, ["Measure", "Value", "Measure", "Value"], [
        ["Flows analysed", f"{flows:,}", "Average bandwidth", f"{avg_bw:.2f} Mbit/s"],
        ["Normal flows", f"{flows - attack_flows:,} ({_pct(flows - attack_flows, flows)})", "95th percentile bandwidth", f"{p95_bw:.2f} Mbit/s"],
        ["Attack flows", f"{attack_flows:,} ({_pct(attack_flows, flows)})", "Peak bandwidth", f"{peak_bw['mbps']:.2f} Mbit/s ({pk(peak_bw)})" if peak_bw else "n/a"],
        ["Average flows per second", f"{flows / secs:.1f}", "Data transferred", f"{total_mb:,.1f} MB"],
        ["Peak flows per second", f"{peak_fl['flows']} ({pk(peak_fl)})" if peak_fl else "n/a", "Alerts per minute (avg)", f"{len(alerts) / mins:.1f}"],
        ["Baseline traffic setting", f"{meta.get('rate', '-')} flows/s", "Dropped flows per minute (avg)", f"{len(dropped) / mins:.1f}"],
    ], [.22, .28, .26, .24], size=7.5)
    ax = _axes(fig, [0.09, y - 0.19, 0.38, 0.16], "flows", "Protocol mix")
    ax.bar(list(proto), list(proto.values()), color=["#6b7686", "#9aa3b2", "#c9ced6"])
    for i, v in enumerate(proto.values()):
        ax.text(i, v, f" {_pct(v, flows, 0)}", ha="center", va="bottom", fontsize=7)
    ax = _axes(fig, [0.57, y - 0.19, 0.36, 0.16], "flows", "Normal vs attack flows")
    ax.bar(["normal", "attack"], [flows - attack_flows, attack_flows], color=["#6b7686", "#d6303f"])
    for i, v in enumerate([flows - attack_flows, attack_flows]):
        ax.text(i, v, f" {v:,}", ha="center", va="bottom", fontsize=7)
    y -= .235
    y = doc.sub(fig, y, "Minute by minute")
    per = defaultdict(lambda: dict(flows=0, alerts=0, dropped=0, mb=[]))
    for p in ser:
        m = per[p["ts"].replace(second=0)]
        m["flows"] += p["flows"]
        m["alerts"] += p["alerts"]
        m["dropped"] += p["dropped"]
        m["mb"].append(p["mbps"])
    minute_rows = [[k.strftime("%H:%M"), v["flows"], v["alerts"], v["dropped"], f"{np.mean(v['mb']):.2f}", f"{max(v['mb']):.2f}"] for k, v in sorted(per.items())]
    shown = minute_rows[-12:]
    y = doc.table(fig, y, ["Minute", "Flows", "Alerts", "Dropped", "Avg Mbit/s", "Peak Mbit/s"], shown or [["-", 0, 0, 0, "-", "-"]], [.16, .16, .16, .16, .18, .18], size=7.5, rh=0.019)
    if len(minute_rows) > 12:
        y = doc.text(fig, y + .01, f"Only the last 12 of {len(minute_rows)} minutes are shown.", color=MUTE, size=8)
    sev = Counter(e["sev"] for e in ev)
    tg = Counter(f"{e['dst']}:{e['port']}" for e in ev).most_common(5)
    y = doc.sub(fig, y, "Most targeted destinations and severity of events")
    doc.table(fig, y, ["Destination", "Events", "Severity", "Events"], [[tg[i][0] if i < len(tg) else "", tg[i][1] if i < len(tg) else "",
                                                                           ["critical", "high", "medium"][i] if i < 3 else "", sev.get(["critical", "high", "medium"][i], 0) if i < 3 else ""]
                                                                          for i in range(max(len(tg), 3))], [.4, .15, .3, .15], size=7.5, rh=0.019)

    # ================================================================ 5. detection performance
    fig, y = doc.page("5. Detection performance")
    y = doc.text(fig, y, "How well the detectors did in this window, measured against what the simulator actually sent. A real sensor does not have this ground truth, so these figures are only possible in a simulation.")
    y = doc.table(fig, y, ["", "Flagged as attack", "Not flagged", "Total"], [
        ["Really an attack", f"{tp:,} (true positives)", f"{fn:,} (missed)", f"{tp + fn:,}"],
        ["Really normal", f"{fp:,} (false alarms)", f"{tn:,} (true negatives)", f"{fp + tn:,}"],
    ], [.3, .27, .27, .16], size=8.5)
    y = doc.table(fig, y, ["Metric", "Value", "Meaning"], [
        ["Detection rate (recall)", _pct(tp, tp + fn), "share of attack flows that were flagged"], ["Precision", _pct(tp, tp + fp), "share of flagged flows that were really attacks"],
        ["False-alarm rate", _pct(fp, fp + tn, 2), "share of normal flows flagged by mistake"], ["F1 score", f"{f1:.3f}" if f1 else "n/a", "balance of precision and recall"],
        ["Accuracy", _pct(tp + tn, flows), "share of all flows judged correctly"],
    ], [.3, .14, .56], size=8)
    y = doc.sub(fig, y, "Detection by true traffic class")
    cls_rows = []
    for c in TRUTH:
        tot = tt[f"{c}|0"] + tt[f"{c}|1"]
        if not tot:
            continue
        hit = tt[f"{c}|1"]
        if c == "normal":
            cls_rows.append([TRUTH[c], f"{tot:,}", f"{hit:,} false alarms", "-", _pct(tot - hit, tot, 2) + " correct", "-"])
        else:
            mine = [e for e in ev if e["truth"] == c]
            cls_rows.append([TRUTH[c], f"{tot:,}", f"{hit:,}", f"{tot - hit:,}", _pct(hit, tot), _pct(sum(e["type"] == EXPECT[c] for e in mine), len(mine)) if mine else "-"])
    y = doc.table(fig, y, ["True class", "Flows", "Flagged", "Missed", "Detection", "Right label"], cls_rows or [["-", "", "", "", "", ""]], [.3, .12, .17, .1, .16, .15], size=7.5, rh=0.02)
    y = doc.sub(fig, y, "Which detector raised the alerts")
    y = doc.table(fig, y, ["Raised by", "Alerts", "Share"], [[k, v, _pct(v, len(alerts), 0)] for k, v in dets.most_common()] or [["-", 0, ""]], [.6, .2, .2], size=8, rh=0.02)
    mm, zd = meta.get("models", {}).get("Voting ensemble"), meta.get("zero_day", {})
    y = doc.sub(fig, y, "Model facts (from training on held-out test data)")
    y = doc.table(fig, y, ["Item", "Value"], [
        ["Voting ensemble macro F1 / false-alarm rate", f"{mm['macro_f1']:.3f} / {mm['false_alarm_rate']:.3f}" if mm else "n/a"],
        ["Unseen botnet flagged: ensemble / K-Means", f"{zd['ensemble']:.1%} / {zd['kmeans']:.1%}" if zd else "n/a"],
        ["K-Means anomaly threshold (distance)", f"{meta['threshold']:.2f}" if meta.get("threshold") else "n/a"],
    ], [.55, .45], size=8, rh=0.02)
    doc.text(fig, y, f"False alarms in this window: {len(fa_ev)}. " + ("Examples: " + "; ".join(_clip(e["request"] or f"{e['src']} -> {e['dst']}", 40) for e in fa_ev[:3]) if fa_ev else "None."), size=8.5)

    # ================================================================ 6. offenders and response
    fig, y = doc.page("6. Offenders and response")
    y = doc.text(fig, y, "Sources ranked by number of attack events, the response statistics of the automatic firewall, and its log (a source is blocked after five alerts).")
    top = sorted(by_src.items(), key=lambda kv: -len(kv[1]))[:10]
    y = doc.table(fig, y, ["Source", "Events", "Alerts", "Dropped", "Main type", "First", "Last"],
                  [[ip, len(it), sum(i["verdict"] == "alert" for i in it), sum(i["verdict"] == "dropped" for i in it),
                    NAME[Counter(i["type"] for i in it).most_common(1)[0][0]], _hms(min(i["ts"] for i in it)), _hms(max(i["ts"] for i in it))] for ip, it in top],
                  [.2, .09, .09, .1, .22, .15, .15])
    y = doc.sub(fig, y, "Response statistics")
    y = doc.table(fig, y, ["Measure", "Value"], [
        ["Sources blocked / blocks expired", f"{len(blocks)} / {sum('expired' in m['msg'] for m in fw)}"],
        ["Time from first alert to block (median / slowest)", f"{np.median(ttb):.1f} s / {max(ttb):.1f} s" if ttb else "n/a"],
        ["Attack flows stopped by the firewall", f"{len(dropped):,} ({_pct(len(dropped), attack_flows)} of attack flows)"],
        ["Distinct attacking sources", f"{len(by_src)}"]], [.6, .4], size=8, rh=0.02)
    y = doc.sub(fig, y, "Firewall log")
    y = doc.table(fig, y, ["Time", "Action"], [[_hms(m["ts"]), _clip(m["msg"].replace("FIREWALL: ", ""), 90)] for m in fw[:14]] or [["-", "No firewall action in this window"]], [.18, .82], size=7.5, rh=0.0195)
    if len(fw) > 14:
        doc.text(fig, y + .01, f"{len(fw) - 14} more firewall actions are not shown.", color=MUTE, size=8)

    # ================================================================ 7. SQL injection and bandwidth
    fig, y = doc.page("7. SQL injection and bandwidth")
    sq = [e for e in ev if e["type"] == "sqli" and e["request"]]
    enc = sum("%" in e["request"] for e in sq)
    y = doc.text(fig, y, f"{len(sq)} requests were classified as SQL injection; {enc} of them used URL encoding to hide the payload. The most frequent distinct requests:")
    reqs = Counter(e["request"] for e in sq).most_common(10)
    y = doc.table(fig, y, ["Request", "Count", "Source examples"], [[_clip(r, 62), c, ", ".join(sorted({e["src"] for e in sq if e["request"] == r})[:2])] for r, c in reqs]
                  or [["none in this window", "", ""]], [.62, .08, .3], size=7.5)
    y = doc.sub(fig, y, "Largest transfers (possible exfiltration or flood traffic)")
    big = sorted(ev, key=lambda e: -e["bytes"])[:8]
    y = doc.table(fig, y, ["Time", "Source", "Target", "Size", "Rate", "Type"],
                  [[_hms(e["ts"]), e["src"], f"{e['dst']}:{e['port']}", f"{e['bytes'] / 1e6:.2f} MB", f"{e['kbps']:,.0f} kbit/s", NAME[e["type"]]] for e in big]
                  or [["-", "", "", "", "", ""]], [.12, .18, .24, .13, .17, .16])
    doc.text(fig, y, "SQL injection is a flaw in the application, so the IDS only detects attempts. The real fix is parameterised queries and input validation.", color=MUTE)

    # ================================================================ 8. recommendations and settings
    fig, y = doc.page("8. Recommendations and settings")
    y = doc.sub(fig, y, "Recommended actions")
    y = doc.bullets(fig, y, [f"{NAME[t]}: {ADVICE[t]}" for t in by_type] or ["No attacks were seen. Keep the baseline running and review the thresholds regularly."], size=9)
    y = doc.sub(fig, y - .01, "Simulation settings and scenarios in this window")
    prow = []
    for i, p in enumerate(phases):
        t1 = phases[i + 1]["ts"] if i + 1 < len(phases) else end
        prow.append([_hms(max(p["ts"], start)), _clip(p["title"], 60), f"{max(0.0, (min(t1, end) - max(p['ts'], start)).total_seconds()):.0f} s"])
    y = doc.table(fig, y, ["Start", "Scenario", "Length"], prow[-14:] or [["-", "none", ""]], [.15, .70, .15], size=7.5, rh=0.0195)
    doc.text(fig, y + .01, f"Baseline normal traffic: {meta.get('rate', '-')} flows per second. Random scenarios: {'on, ' + meta.get('level', '') if meta.get('auto') else 'off'}.", size=8.5, color=MUTE)
    y -= .02
    y = doc.sub(fig, y, "Limits of this report")
    doc.bullets(fig, y, [
        "The traffic is simulated, so detection and false-alarm rates are measured against known ground truth. A real sensor never has it.",
        "Automatic blocking can lock out legitimate users (for example a flash crowd). Review blocks before making them permanent.",
        "Low-and-slow attacks and obfuscated payloads can stay under the thresholds; combine the IDS with a firewall, a WAF and patching.",
        "Logs contain addresses and request text. Store this report and the alert log with access control and a retention limit.",
    ], size=9)

    # ================================================================ appendix: alert log
    per_page = 40
    log = sorted(ev, key=lambda e: e["ts"])[:600]
    chunks = [log[i:i + per_page] for i in range(0, len(log), per_page)] or [[]]
    for n, chunk in enumerate(chunks, 1):
        fig, y = doc.page(f"Appendix A. Alert log ({n} of {len(chunks)})")
        if n == 1:
            y = doc.text(fig, y, f"Every attack event in the window, oldest first ({len(log)} of {len(ev)} shown; * = dropped because the source was already blocked).", color=MUTE)
        doc.table(fig, y, ["Time", "Sev", "Type", "Source -> target", "Evidence", "By"],
                  [[_hms(e["ts"]), e["sev"] or "-", NAME[e["type"]].split(" (")[0] + (" *" if e["verdict"] == "dropped" else ""), _clip(f"{e['src']} -> {e['dst']}:{e['port']}", 34),
                    _clip(e["request"] or e["detail"] or "source already blocked", 36), _clip(e["by"], 18)] for e in chunk] or [["-", "", "", "", "no attack events", ""]],
                  [.09, .07, .14, .26, .27, .17], size=6.5, rh=0.0185)
    return doc.save(previews)
