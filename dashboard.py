"""Security-operations dashboard:   uvicorn dashboard:app --port 8001    then open http://127.0.0.1:8001/

A background thread runs the live detection engine (engine.py); the page polls /api/state once a second.
The "red team" buttons start attacks on demand, so you can watch the detectors and the firewall react.
"""
import json
import os
import re
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

os.environ.setdefault("LOKY_MAX_CPU_COUNT", "4")

from fastapi import FastAPI, HTTPException  # noqa: E402
from fastapi.responses import FileResponse, Response  # noqa: E402

from engine import LEVELS, PHASES, TICK, Engine  # noqa: E402
from report import build_report  # noqa: E402

ROOT = Path(__file__).resolve().parent
engine = Engine()


def _loop():
    while True:
        t0 = time.time()
        try:
            engine.step()
        except Exception as exc:          # keep the simulation alive whatever happens in one tick
            print("[engine] tick failed:", exc)
        time.sleep(max(0.01, TICK - (time.time() - t0)))


@asynccontextmanager
async def lifespan(_):
    threading.Thread(target=_loop, daemon=True).start()
    yield


app = FastAPI(title="Network Intrusion Detection - SOC dashboard", lifespan=lifespan)


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(ROOT / "ui" / "index.html")


@app.get("/api/state")
def state(since: int = 0):
    return engine.state(since)


@app.post("/api/attack/{key}")
def attack(key: str):
    if key not in PHASES or key == "normal":
        raise HTTPException(status_code=404, detail=f"Unknown attack. Choose one of {[k for k in PHASES if k != 'normal']}")
    engine.launch(key)
    return {"queued": key}


@app.post("/api/random")
def random_attack():
    return {"queued": engine.random_scenario()}


@app.post("/api/auto")
def auto(on: bool, level: str = "normal"):
    if level not in LEVELS:
        raise HTTPException(status_code=422, detail=f"level must be one of {list(LEVELS)}")
    engine.set_auto(on, level)
    return {"auto": engine.auto, "level": engine.level}


@app.post("/api/timer")
def timer(minutes: int = 0, until: str = "", fresh: bool = True):
    """Run the simulation for `minutes` (1-720) or until the clock shows `until` (HH:MM), then stop."""
    if until:
        if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", until):
            raise HTTPException(status_code=422, detail="until must look like 14:30")
    elif not 1 <= minutes <= 720:
        raise HTTPException(status_code=422, detail="minutes must be between 1 and 720")
    engine.set_timer(minutes or None, until or None, fresh)
    return {"until": engine.state()["timer"]["until"]}


@app.post("/api/timer/cancel")
def timer_cancel():
    engine.cancel_timer()
    return {"ok": True}


@app.post("/api/rate")
def rate(value: int):
    engine.set_rate(value)
    return {"rate": engine.base_rate}


@app.get("/api/report")
def report(minutes: int = 0):
    """PDF attack report (6+ pages) for the last `minutes` of traffic; 0 = since the start."""
    if minutes < 0 or minutes > 24 * 60:
        raise HTTPException(status_code=422, detail="minutes must be between 0 and 1440")
    pdf, pages = build_report(engine.report_data(minutes or None))
    return Response(pdf, media_type="application/pdf", headers={"Content-Disposition": 'attachment; filename="attack-report.pdf"', "X-Pages": str(pages)})


@app.post("/api/scenario")
def scenario():
    engine.run_scenario()
    return {"queued": "full scenario"}


@app.post("/api/pause")
def pause():
    engine.paused = not engine.paused
    return {"paused": engine.paused}


@app.post("/api/unblock")
def unblock():
    engine.unblock_all()
    return {"ok": True}


@app.post("/api/reset")
def reset():
    engine.reset()
    return {"ok": True}


@app.get("/api/model")
def model():
    path = ROOT / "reports" / "results.json"
    if not path.exists():
        raise HTTPException(status_code=503, detail="Run python train.py first.")
    return json.loads(path.read_text(encoding="utf-8"))
