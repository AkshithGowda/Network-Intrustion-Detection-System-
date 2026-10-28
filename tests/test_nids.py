import numpy as np
import pytest

from traffic import CLASSES, FEATURES, ZERO_DAY, make_flows, request_features


def test_request_features_spot_sql_injection():
    bad = request_features("GET /products?id=1 UNION SELECT username,password FROM users--")
    enc = request_features("GET /search?q=%27+OR+1%3D1--")             # URL-encoded payload is decoded first
    ok = request_features("GET /search?q=temple+timings")
    assert bad["n_sql_kw"] >= 2 and enc["n_sql_kw"] >= 1 and enc["pct_enc"] > 0
    assert ok["n_sql_kw"] == 0 and ok["n_special"] == 0
    assert request_features("")["url_len"] == 0


def test_generator_shape_and_labels():
    df = make_flows(600, {k: 1 for k in CLASSES + [ZERO_DAY]}, np.random.default_rng(0))
    assert list(df[FEATURES].columns) == FEATURES and not df[FEATURES].isna().any().any()
    assert set(df["label"]) == set(CLASSES + [ZERO_DAY])
    assert df.loc[df["label"] == "sqli", "n_sql_kw"].mean() > df.loc[df["label"] == "normal", "n_sql_kw"].mean()
    assert df.loc[df["label"] == "exfil", "bandwidth_kbps"].median() > 10 * df.loc[df["label"] == "normal", "bandwidth_kbps"].median()


@pytest.fixture(scope="module")
def engine():
    pytest.importorskip("joblib")
    from engine import ROOT, Engine
    if not (ROOT / "models" / "ids.joblib").exists():
        pytest.skip("run python train.py first")
    return Engine(seed=3)


def test_engine_detects_attacks_and_blocks(engine):
    engine.reset()
    engine.launch("dos")
    for _ in range(16):
        engine.step()
    s = engine.state()
    assert s["kpi"]["detection"] > 0.9 and s["kpi"]["blocked"] > 0 and s["by_type"].get("dos", 0) > 0


def test_dashboard_api(engine):
    from fastapi.testclient import TestClient

    import dashboard
    c = TestClient(dashboard.app)
    assert c.get("/").status_code == 200
    assert c.get("/api/state").json()["threat"] in ("LOW", "ELEVATED", "HIGH", "CRITICAL")
    assert c.post("/api/attack/rm-rf").status_code == 404
    assert c.post("/api/attack/sqli").json() == {"queued": "sqli"}


def test_report_has_at_least_five_pages(engine):
    from report import build_report
    engine.reset()
    engine.launch("sqli")
    for _ in range(30):
        engine.step()
    pdf, pages = build_report(engine.report_data(5))
    assert pdf[:4] == b"%PDF" and pages >= 5
    engine.reset()
    assert build_report(engine.report_data(5))[1] >= 5               # still a full report when there was no attack


def test_random_scenarios_and_flash_crowd(engine):
    engine.reset()
    kinds = {engine.random_scenario() for _ in range(60)}
    assert kinds <= {"dos", "probe", "brute_force", "sqli", "exfil", "botnet", "flash"} and len(kinds) > 3
    engine.reset()
    engine.set_auto(True, "busy")
    for _ in range(120):                                             # one minute of quiet time: auto mode must start something
        engine.step()
    assert engine.report_data(None)["phases"] and any(p["key"] != "idle" for p in engine.report_data(None)["phases"])
    engine.set_auto(False)


def test_report_and_auto_api(engine):
    from fastapi.testclient import TestClient

    import dashboard
    c = TestClient(dashboard.app)
    r = c.get("/api/report?minutes=5")
    assert r.status_code == 200 and r.content[:4] == b"%PDF" and int(r.headers["X-Pages"]) >= 5
    assert c.get("/api/report?minutes=99999").status_code == 422
    assert c.post("/api/auto?on=true&level=x").status_code == 422
    assert c.post("/api/auto?on=false&level=calm").json() == {"auto": False, "level": "calm"}
    assert c.post("/api/rate?value=500").json() == {"rate": 40}
    c.post("/api/rate?value=10")


def test_timed_run_stops_by_itself(engine):
    engine.reset()
    engine.set_timer(minutes=0.1)                                    # 6 simulated seconds = 12 steps
    for _ in range(30):
        engine.step()
    t = engine.state()["timer"]
    assert t["finished"] and not t["active"] and engine.paused
    flows = engine.state()["kpi"]["flows"]
    engine.step()
    assert engine.state()["kpi"]["flows"] == flows                   # nothing more is simulated after the end
    engine.cancel_timer()
    assert not engine.paused and not engine.state()["timer"]["finished"]


def test_timer_api_validation(engine):
    from fastapi.testclient import TestClient

    import dashboard
    c = TestClient(dashboard.app)
    assert c.post("/api/timer?minutes=0").status_code == 422
    assert c.post("/api/timer?minutes=9999").status_code == 422
    assert c.post("/api/timer?until=25:99").status_code == 422
    assert c.post("/api/timer?minutes=2").status_code == 200 and c.get("/api/state").json()["timer"]["active"]
    assert c.post("/api/timer?until=23:59").status_code == 200
    assert c.post("/api/timer/cancel").status_code == 200 and not c.get("/api/state").json()["timer"]["active"]
