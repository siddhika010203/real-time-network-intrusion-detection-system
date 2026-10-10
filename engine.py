"""
The detection engine.

Owns the packet queue, drains it into the window aggregator, closes windows on
schedule, runs both detectors over every window, and publishes alerts plus a
stats frame.

Runs in its own thread so a slow model never stalls packet capture.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from typing import Callable, List, Optional

from .alerts import AlertManager
from .capture import build_capture
from .features import WindowAggregator
from .ml import MLDetector
from .rules import RuleEngine
from .schema import PacketRecord, StatsFrame

log = logging.getLogger("nids.engine")


class DetectionEngine(threading.Thread):
    def __init__(self, cfg):
        super().__init__(daemon=True, name="DetectionEngine")
        self.cfg = cfg
        self.queue: "queue.Queue[PacketRecord]" = queue.Queue(maxsize=cfg.queue_maxsize)

        self.capture = build_capture(cfg, self.queue)
        self.aggregator = WindowAggregator(cfg.window_seconds, cfg.auth_ports)
        self.rule_engine = RuleEngine(cfg)
        self.ml_detector = MLDetector(cfg)
        self.alert_manager = AlertManager(cfg)

        self._stop_event = threading.Event()
        self._stats_subscribers: List[Callable[[dict], None]] = []

        self.started_at = 0.0
        self.total_packets = 0
        self.windows_processed = 0
        self.last_stats: Optional[StatsFrame] = None

    # -- wiring ----------------------------------------------------------

    def on_alert(self, callback) -> None:
        self.alert_manager.subscribe(callback)

    def on_stats(self, callback) -> None:
        self._stats_subscribers.append(callback)

    # -- lifecycle -------------------------------------------------------

    def start_all(self) -> None:
        self.started_at = time.time()
        self.capture.start()
        self.start()
        log.info(
            "engine running | mode=%s | window=%.1fs | ML=%s",
            self.capture.mode, self.cfg.window_seconds,
            "on" if self.ml_detector.available else "off",
        )

    def stop_all(self) -> None:
        self._stop_event.set()
        self.capture.stop()

    # -- main loop -------------------------------------------------------

    def run(self) -> None:
        last_window = time.time()

        while not self._stop_event.is_set():
            # Drain whatever is queued, but yield periodically so windows
            # still close on time under a sustained flood.
            deadline = time.time() + 0.25
            while time.time() < deadline:
                try:
                    pkt = self.queue.get(timeout=0.05)
                except queue.Empty:
                    break
                self.aggregator.add(pkt)
                self.total_packets += 1

            now = time.time()
            if (now - last_window) >= self.cfg.window_seconds:
                try:
                    self._close_window(now)
                except Exception as exc:
                    log.exception("window processing failed: %s", exc)
                last_window = now

    def _close_window(self, now: float) -> None:
        windows = self.aggregator.flush(now)
        auth_hits = getattr(self.aggregator, "last_auth_hits", {})
        top_talkers = self.aggregator.top_talkers()
        protocol_mix = self.aggregator.protocol_mix

        produced = []
        for features in windows:
            alerts = self.rule_engine.evaluate(features, auth_hits.get(features.src_ip))
            alerts += self.ml_detector.evaluate(features)
            if alerts:
                produced.extend(self.alert_manager.submit_many(alerts))

        self.windows_processed += 1
        self._publish_stats(now, windows, top_talkers, protocol_mix)

    def _publish_stats(self, now, windows, top_talkers, protocol_mix) -> None:
        window_packets = sum(w.packet_count for w in windows)
        window_bytes = sum(w.byte_count for w in windows)
        span = max(self.cfg.window_seconds, 0.001)

        frame = StatsFrame(
            ts=now,
            packets_per_sec=round(window_packets / span, 1),
            bytes_per_sec=round(window_bytes / span, 1),
            active_sources=len(windows),
            total_packets=self.total_packets,
            total_alerts=self.alert_manager.total_alerts,
            top_talkers=top_talkers,
            protocol_mix=protocol_mix,
            model_loaded=self.ml_detector.available,
            capture_mode=self.capture.mode,
            interface=getattr(self.capture, "interface", None)
            or getattr(self.capture, "pcap_file", None),
        )
        self.last_stats = frame
        payload = frame.to_dict()
        payload["dropped_packets"] = self.capture.dropped
        payload["uptime_seconds"] = round(now - self.started_at, 1)

        for callback in self._stats_subscribers:
            try:
                callback(payload)
            except Exception as exc:
                log.debug("stats subscriber failed: %s", exc)

    # -- health ----------------------------------------------------------

    def health(self) -> dict:
        return {
            "running": self.is_alive(),
            "capture_alive": self.capture.is_alive(),
            "capture_mode": self.capture.mode,
            "packets_captured": self.capture.captured,
            "packets_dropped": self.capture.dropped,
            "packets_processed": self.total_packets,
            "queue_depth": self.queue.qsize(),
            "windows_processed": self.windows_processed,
            "ml_enabled": self.ml_detector.available,
            "total_alerts": self.alert_manager.total_alerts,
            "uptime_seconds": round(time.time() - self.started_at, 1)
            if self.started_at else 0,
        }
