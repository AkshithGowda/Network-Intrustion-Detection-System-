# Network Intrusion Detection System (ML mini project)

Decision tree, bagging, AdaBoost, random forest, soft-voting ensemble and K-Means, with a real-time traffic
simulation, a security-operations dashboard and an attack report. Runs offline: `traffic.py` generates the traffic.

Evidence per flow (22 features): bandwidth/flow statistics, access-log behaviour (visits per minute, failed logins,
4xx share) and SQL-injection indicators parsed from the HTTP request text.

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python train.py                       # train and compare the models; writes models/ and reports/
python simulate.py --fast             # console simulation of the scripted scenario
python simulate.py --fast --minutes 5 --level busy   # random scenarios for 5 simulated minutes
uvicorn dashboard:app --port 8001     # dashboard at http://127.0.0.1:8001/
python -m pytest -q                   # 9 tests (run train.py first)
```

## Dashboard

- **Situation strip, traffic charts, attack types, alerts (MITRE ATT&CK), live feed, SQL-injection monitor, firewall.**
- **Console:** launch each of six attacks, run the full scenario, pause, unblock, reset.
- **Traffic generator:** normal traffic always runs (rate 2-40 flows/s); a flash crowd (harmless surge); a random scenario
  now; auto mode (calm / normal / busy) that starts random attacks after random quiet periods.
- **Timed run:** simulate for N minutes or until a clock time, then stop. Optional counter reset and automatic report.
- **Attack report:** PDF of 9+ pages for the last 5/15/30/60 minutes or since the start: summary, timeline, attack
  breakdown, traffic statistics, detection performance (confusion matrix, precision, recall, per-class detection),
  offenders and response, SQL injection and bandwidth, recommendations and settings, full alert log.

| File | Purpose |
|---|---|
| `traffic.py` | traffic generator and SQL-injection feature extractor |
| `train.py` | trains/compares the models, builds the K-Means anomaly detector |
| `engine.py` | real-time engine: scoring, alerts, firewall, random/auto/timed modes, history |
| `report.py` | builds the attack report PDF |
| `simulate.py` | console simulation |
| `dashboard.py`, `ui/index.html` | web dashboard and its API |
| `DESIGN_PROMPT.md` | the UI design brief used for the revamp |

Notes: results are on simulated data, not a real network. The dashboard has attack buttons and no login; keep it on
127.0.0.1.
