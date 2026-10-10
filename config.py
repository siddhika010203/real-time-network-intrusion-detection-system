"""Tunables in one place. Override any of them with environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _env_int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, default))
    except (TypeError, ValueError):
        return default


def _env_float(key: str, default: float) -> float:
    try:
        return float(os.environ.get(key, default))
    except (TypeError, ValueError):
        return default


@dataclass
class Config:
    # ---- capture -------------------------------------------------------
    interface: str | None = os.environ.get("NIDS_IFACE") or None
    bpf_filter: str = os.environ.get("NIDS_BPF", "ip")
    pcap_file: str | None = os.environ.get("NIDS_PCAP") or None
    replay_speed: float = _env_float("NIDS_REPLAY_SPEED", 1.0)

    # ---- windowing -----------------------------------------------------
    window_seconds: float = _env_float("NIDS_WINDOW", 5.0)
    queue_maxsize: int = _env_int("NIDS_QUEUE", 50_000)

    # ---- rule thresholds -----------------------------------------------
    # Port scan: distinct destination ports touched by one source per window.
    port_scan_ports: int = _env_int("NIDS_PORTSCAN_PORTS", 20)
    # Host sweep: distinct destination hosts touched by one source per window.
    host_sweep_hosts: int = _env_int("NIDS_SWEEP_HOSTS", 15)
    # SYN flood: half-open handshakes per window and the SYN:total ratio.
    syn_flood_count: int = _env_int("NIDS_SYNFLOOD_COUNT", 150)
    syn_flood_ratio: float = _env_float("NIDS_SYNFLOOD_RATIO", 0.7)
    # Volumetric flood: packets per second from a single source.
    dos_pps: float = _env_float("NIDS_DOS_PPS", 800.0)
    dos_bps: float = _env_float("NIDS_DOS_BPS", 4_000_000.0)
    # Brute force: repeated connections to one auth port from one source.
    brute_force_attempts: int = _env_int("NIDS_BRUTE_ATTEMPTS", 40)
    auth_ports: tuple = (21, 22, 23, 3389, 3306, 5432, 1433, 5900)

    # ---- ML ------------------------------------------------------------
    model_dir: str = os.environ.get("NIDS_MODEL_DIR", "models")
    ml_min_packets: int = _env_int("NIDS_ML_MIN_PACKETS", 10)
    ml_confidence_floor: float = _env_float("NIDS_ML_CONF", 0.75)

    # ---- alerting ------------------------------------------------------
    db_path: str = os.environ.get("NIDS_DB", "data/alerts.db")
    dedup_cooldown: float = _env_float("NIDS_DEDUP_COOLDOWN", 60.0)
    alert_buffer: int = _env_int("NIDS_ALERT_BUFFER", 500)

    # ---- allow-list ----------------------------------------------------
    # Sources that never raise alerts. Put your scanner/monitoring hosts here.
    whitelist: tuple = tuple(
        filter(None, os.environ.get("NIDS_WHITELIST", "").split(","))
    )

    # ---- server --------------------------------------------------------
    host: str = os.environ.get("NIDS_HOST", "127.0.0.1")
    port: int = _env_int("NIDS_PORT", 8000)


CONFIG = Config()
