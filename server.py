"""
FastAPI application: REST for history, WebSocket for the live feed.

The engine runs on threads and the server on asyncio, so every push from the
engine is handed across with run_coroutine_threadsafe. Getting that boundary
wrong is the usual reason a dashboard like this freezes after a few minutes.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .config import CONFIG
from .engine import DetectionEngine

log = logging.getLogger("nids.server")

STATIC_DIR = Path(__file__).parent / "static"


class ConnectionManager:
    """Tracks open sockets and fans messages out to all of them."""

    def __init__(self) -> None:
        self.active: Set[WebSocket] = set()
        self.loop: asyncio.AbstractEventLoop | None = None

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.active.add(ws)
        log.info("dashboard connected (%d open)", len(self.active))

    def disconnect(self, ws: WebSocket) -> None:
        self.active.discard(ws)

    async def _broadcast(self, message: dict) -> None:
        if not self.active:
            return
        payload = json.dumps(message, default=str)
        dead = []
        for ws in list(self.active):
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    def broadcast_threadsafe(self, message: dict) -> None:
        """Called from engine threads. Never blocks the caller."""
        if self.loop is None or self.loop.is_closed():
            return
        asyncio.run_coroutine_threadsafe(self._broadcast(message), self.loop)


manager = ConnectionManager()
engine = DetectionEngine(CONFIG)

app = FastAPI(title="Real-Time Network Intrusion Detection System", version="1.0")


# --------------------------------------------------------------------------
# Lifecycle
# --------------------------------------------------------------------------

@app.on_event("startup")
async def startup() -> None:
    manager.loop = asyncio.get_running_loop()
    engine.on_alert(lambda a: manager.broadcast_threadsafe({"type": "alert", "data": a}))
    engine.on_stats(lambda s: manager.broadcast_threadsafe({"type": "stats", "data": s}))
    engine.start_all()


@app.on_event("shutdown")
async def shutdown() -> None:
    engine.stop_all()


# --------------------------------------------------------------------------
# REST
# --------------------------------------------------------------------------

@app.get("/api/health")
async def health():
    return engine.health()


@app.get("/api/alerts")
async def alerts(limit: int = 100, severity: str | None = None):
    return {"alerts": engine.alert_manager.store.recent(limit=limit, severity=severity)}


@app.get("/api/summary")
async def summary(hours: int = 24):
    since = time.time() - hours * 3600
    data = engine.alert_manager.store.summary(since=since)
    data["window_hours"] = hours
    return data


@app.get("/api/stats")
async def stats():
    if engine.last_stats is None:
        return JSONResponse({"detail": "no window has closed yet"}, status_code=503)
    return engine.last_stats.to_dict()


@app.get("/api/config")
async def config():
    """Thresholds currently in force. Useful when tuning during a demo."""
    return {
        "window_seconds": CONFIG.window_seconds,
        "port_scan_ports": CONFIG.port_scan_ports,
        "host_sweep_hosts": CONFIG.host_sweep_hosts,
        "syn_flood_count": CONFIG.syn_flood_count,
        "dos_pps": CONFIG.dos_pps,
        "brute_force_attempts": CONFIG.brute_force_attempts,
        "ml_confidence_floor": CONFIG.ml_confidence_floor,
        "whitelist": list(CONFIG.whitelist),
    }


# --------------------------------------------------------------------------
# WebSocket
# --------------------------------------------------------------------------

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        # Backfill so a freshly opened dashboard is not blank.
        await ws.send_text(json.dumps({
            "type": "snapshot",
            "data": {
                "alerts": engine.alert_manager.store.recent(limit=50),
                "health": engine.health(),
                "stats": engine.last_stats.to_dict() if engine.last_stats else None,
            },
        }, default=str))

        while True:
            # Keeps the socket open; the client sends a ping every 30s.
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)
    except Exception:
        manager.disconnect(ws)


# --------------------------------------------------------------------------
# Dashboard
# --------------------------------------------------------------------------

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def dashboard():
    return FileResponse(str(STATIC_DIR / "index.html"))
