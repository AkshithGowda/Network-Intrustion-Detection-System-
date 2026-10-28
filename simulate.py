"""Console simulation of live traffic:   python simulate.py [--fast] [--no-color]

Runs the scripted scenario (normal -> DoS -> scan -> brute force -> SQL injection -> exfiltration -> unknown botnet)
through the same detection engine as the dashboard and prints what a security analyst would see.
"""
import argparse
import csv
import os
import sys
import time
import warnings
from pathlib import Path

os.environ.setdefault("LOKY_MAX_CPU_COUNT", "4")
warnings.filterwarnings("ignore")

from engine import SCENARIO, TICK, Engine  # noqa: E402

ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument("--fast", action="store_true", help="do not wait between ticks")
ap.add_argument("--no-color", action="store_true")
ap.add_argument("--minutes", type=float, help="instead of the scripted scenario: random scenarios for this many simulated minutes")
ap.add_argument("--level", default="normal", choices=["calm", "normal", "busy"], help="how often random scenarios start (with --minutes)")
ap.add_argument("--all", action="store_true", help="print every normal flow (default: one in eight)")
a = ap.parse_args()
os.system("")                                          # enables ANSI colours in the Windows console
C = {k: "" if a.no_color else v for k, v in dict(r="\033[91m", y="\033[93m", g="\033[92m", c="\033[96m", d="\033[90m", b="\033[1m", z="\033[0m").items()}

eng = Engine()
if a.minutes:
    eng.set_auto(True, a.level)
    eng.set_timer(minutes=a.minutes)
else:
    eng.run_scenario()
rows, shown, last_phase = [], 0, None
print(f"{C['b']}NETWORK INTRUSION DETECTION - live simulation{C['z']}  ({len(SCENARIO)} phases, ensemble + K-Means detector)\n")
while not eng.state()["timer"]["finished"] if a.minutes else not eng.idle():
    evs = eng.step()
    title = eng.cur["title"] if eng.cur else ""
    if title != last_phase and eng.cur and eng.cur["key"] != "idle":
        print(f"\n{C['c']}{C['b']}=== {title} ==={C['z']}")
        last_phase = title
    for e in evs:
        if e["kind"] == "fw":
            print(f"{C['y']}{e['t']}  {e['msg']}{C['z']}")
            continue
        rows.append(e)
        req = (" " + e["request"][:60]) if e["request"] else ""
        line = f"{e['t']}  {e['src']:<15} -> {e['dst']}:{e['port']:<5} {e['proto']:<4} {e['kbps']:>9,.0f} kbps{req}"
        if e["verdict"] == "alert":
            print(f"{C['r']}{C['b']}[ALERT {e['sev'].upper():<8}]{C['z']}{C['r']} {line}\n    -> {e['type'].upper()} ({e['by']}, {e['mitre']}): {e['detail']}{C['z']}")
        elif e["verdict"] == "dropped":
            print(f"{C['d']}[DROPPED       ] {line}{C['z']}")
        else:
            shown += 1
            if a.all or shown % 8 == 0:
                print(f"{C['g']}[ok           ]{C['z']}{C['d']} {line}{C['z']}")
    if not a.fast:
        time.sleep(TICK)

s = eng.state()
k = s["kpi"]
print(f"\n{C['b']}SUMMARY{C['z']}")
print(f"  flows analysed   {k['flows']}   attack flows {k['attacks']}   alerts {k['alerts']}   dropped by firewall {k['dropped']}")
print(f"  detection rate   {k['detection']:.1%}   false-alarm rate {k['false_alarm']:.1%}")
print("  alerts by type  ", ", ".join(f"{t} {n}" for t, n in sorted(s["by_type"].items(), key=lambda t: -t[1])))
out = Path(__file__).resolve().parent / "reports" / "alerts.csv"
out.parent.mkdir(exist_ok=True)
with open(out, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["time", "verdict", "type", "severity", "src", "dst", "port", "kbps", "request", "truth", "mitre", "detail"])
    for e in rows:
        if e["verdict"] != "ok":
            w.writerow([e["t"], e["verdict"], e["type"], e["sev"], e["src"], e["dst"], e["port"], e["kbps"], e["request"], e["truth"], e["mitre"], e["detail"]])
print(f"  alert log saved  {out}")
