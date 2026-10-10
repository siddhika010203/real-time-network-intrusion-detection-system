"""
Alert handling: deduplicate, persist, broadcast.

The dedup layer matters more than it sounds. A port scan produces an alert on
every window it spans; without suppression the dashboard fills with the same
line and the operator stops reading it. Repeats inside the cooldown increment
a counter on the original alert instead.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from collections import deque
from typing import Callable, Dict, List, Optional

from .schema import Alert, SEVERITY_ORDER

log = logging.getLogger("nids.alerts")

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id     TEXT PRIMARY KEY,
    detected_at  REAL NOT NULL,
    threat_type  TEXT NOT NULL,
    src_ip       TEXT NOT NULL,
    severity     TEXT NOT NULL,
    detector     TEXT NOT NULL,
    confidence   REAL NOT NULL,
    description  TEXT NOT NULL,
    evidence     TEXT NOT NULL,
    repeat_count INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_src  ON alerts(src_ip);
"""


class AlertStore:
    """SQLite-backed history. One connection, guarded by a lock."""

    def __init__(self, db_path: str):
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def insert(self, alert: Alert) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    alert.alert_id, alert.detected_at, alert.threat_type,
                    alert.src_ip, alert.severity, alert.detector,
                    alert.confidence, alert.description,
                    json.dumps(alert.evidence), 1,
                ),
            )
            self._conn.commit()

    def bump(self, alert_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE alerts SET repeat_count = repeat_count + 1 WHERE alert_id = ?",
                (alert_id,),
            )
            self._conn.commit()

    def recent(self, limit: int = 100, severity: str | None = None) -> List[dict]:
        sql = "SELECT * FROM alerts"
        params: list = []
        if severity:
            sql += " WHERE severity = ?"
            params.append(severity)
        sql += " ORDER BY detected_at DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def summary(self, since: float = 0.0) -> dict:
        with self._lock:
            by_sev = self._conn.execute(
                "SELECT severity, COUNT(*) c FROM alerts WHERE detected_at >= ? "
                "GROUP BY severity", (since,)
            ).fetchall()
            by_type = self._conn.execute(
                "SELECT threat_type, COUNT(*) c FROM alerts WHERE detected_at >= ? "
                "GROUP BY threat_type ORDER BY c DESC LIMIT 10", (since,)
            ).fetchall()
            offenders = self._conn.execute(
                "SELECT src_ip, COUNT(*) c FROM alerts WHERE detected_at >= ? "
                "GROUP BY src_ip ORDER BY c DESC LIMIT 10", (since,)
            ).fetchall()
            total = self._conn.execute(
                "SELECT COUNT(*) c FROM alerts WHERE detected_at >= ?", (since,)
            ).fetchone()["c"]
        return {
            "total": total,
            "by_severity": {r["severity"]: r["c"] for r in by_sev},
            "by_type": {r["threat_type"]: r["c"] for r in by_type},
            "top_offenders": [{"ip": r["src_ip"], "count": r["c"]} for r in offenders],
        }

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        try:
            d["evidence"] = json.loads(d["evidence"])
        except (TypeError, ValueError):
            d["evidence"] = {}
        d["detected_at_iso"] = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(d["detected_at"])
        )
        return d

    def close(self) -> None:
        with self._lock:
            self._conn.close()


class AlertManager:
    """Dedup + persist + fan out to subscribers (the WebSocket layer)."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.store = AlertStore(cfg.db_path)
        self.buffer: deque = deque(maxlen=cfg.alert_buffer)
        self._last_seen: Dict[str, tuple[float, str]] = {}   # key -> (ts, alert_id)
        self._subscribers: List[Callable[[dict], None]] = []
        self._lock = threading.Lock()
        self.total_alerts = 0

    def subscribe(self, callback: Callable[[dict], None]) -> None:
        self._subscribers.append(callback)

    def submit(self, alert: Alert) -> Optional[dict]:
        """Returns the alert dict if it was new, None if suppressed as a repeat."""
        now = time.time()
        key = alert.dedup_key

        with self._lock:
            previous = self._last_seen.get(key)
            if previous and (now - previous[0]) < self.cfg.dedup_cooldown:
                self.store.bump(previous[1])
                return None
            self._last_seen[key] = (now, alert.alert_id)
            self.total_alerts += 1

        payload = alert.to_dict()
        self.store.insert(alert)
        self.buffer.append(payload)

        for callback in self._subscribers:
            try:
                callback(payload)
            except Exception as exc:
                log.debug("subscriber failed: %s", exc)

        log.warning(
            "[%s] %s from %s (%s)",
            alert.severity.upper(), alert.threat_type, alert.src_ip, alert.detector,
        )
        return payload

    def submit_many(self, alerts: List[Alert]) -> List[dict]:
        """
        Submit a window's worth of alerts, worst first, so that if two
        detectors fire on the same source the operator sees the severe one.
        """
        ordered = sorted(
            alerts, key=lambda a: SEVERITY_ORDER.get(a.severity, 0), reverse=True
        )
        return [p for a in ordered if (p := self.submit(a)) is not None]

    def recent(self, limit: int = 50) -> List[dict]:
        return list(self.buffer)[-limit:][::-1]
