"""
Frozen data contracts.

Every other module depends on these shapes. Change them here and nowhere else,
or the rule engine, the ML layer and the dashboard will silently disagree.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional


# --------------------------------------------------------------------------
# Layer 1: a single captured packet, flattened
# --------------------------------------------------------------------------

@dataclass(slots=True)
class PacketRecord:
    """One packet, reduced to the fields the detectors actually use."""

    ts: float                  # epoch seconds, from the capture layer
    src_ip: str
    dst_ip: str
    protocol: str              # "TCP" | "UDP" | "ICMP" | "OTHER"
    src_port: int = 0          # 0 when the protocol has no ports
    dst_port: int = 0
    length: int = 0            # bytes on the wire
    tcp_flags: str = ""        # e.g. "S", "SA", "FA", "R"

    @property
    def is_syn_only(self) -> bool:
        """SYN set, ACK clear - the opening packet of a TCP handshake."""
        return "S" in self.tcp_flags and "A" not in self.tcp_flags


# --------------------------------------------------------------------------
# Layer 2: one source IP aggregated over one time window
# --------------------------------------------------------------------------

# The feature vector. Order matters: training and inference both read this list.
FEATURE_NAMES = [
    "packet_count",
    "byte_count",
    "mean_packet_size",
    "distinct_dst_ports",
    "distinct_dst_ips",
    "syn_count",
    "syn_ratio",
    "rst_count",
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
    "packets_per_sec",
    "bytes_per_sec",
    "port_entropy",
]


@dataclass(slots=True)
class FlowFeatures:
    """Aggregated behaviour of one source IP over one window."""

    src_ip: str
    window_start: float
    window_end: float

    packet_count: int = 0
    byte_count: int = 0
    mean_packet_size: float = 0.0
    distinct_dst_ports: int = 0
    distinct_dst_ips: int = 0
    syn_count: int = 0
    syn_ratio: float = 0.0
    rst_count: int = 0
    tcp_ratio: float = 0.0
    udp_ratio: float = 0.0
    icmp_ratio: float = 0.0
    packets_per_sec: float = 0.0
    bytes_per_sec: float = 0.0
    port_entropy: float = 0.0

    def vector(self) -> list[float]:
        """Feature vector in FEATURE_NAMES order. Used by the ML layer."""
        return [float(getattr(self, name)) for name in FEATURE_NAMES]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------
# Layer 3: an alert
# --------------------------------------------------------------------------

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass(slots=True)
class Alert:
    """
    What the rule engine and the ML layer both emit, and what the dashboard
    renders. Both detectors produce this identical shape - that is the whole
    point of declaring it here.
    """

    threat_type: str                       # "port_scan", "syn_flood", ...
    src_ip: str
    severity: str                          # low | medium | high | critical
    detector: str                          # "rule" | "ml"
    description: str
    detected_at: float = field(default_factory=time.time)
    confidence: float = 1.0                # rules are 1.0; ML reports its own
    evidence: Dict[str, Any] = field(default_factory=dict)
    alert_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["detected_at_iso"] = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(self.detected_at)
        )
        return d

    @property
    def dedup_key(self) -> str:
        """Alerts sharing this key inside the cooldown are counted, not repeated."""
        return f"{self.threat_type}:{self.src_ip}"


# --------------------------------------------------------------------------
# Layer 4: the periodic stats frame pushed to the dashboard
# --------------------------------------------------------------------------

@dataclass(slots=True)
class StatsFrame:
    ts: float
    packets_per_sec: float
    bytes_per_sec: float
    active_sources: int
    total_packets: int
    total_alerts: int
    top_talkers: list = field(default_factory=list)   # [{"ip":..,"packets":..}]
    protocol_mix: Dict[str, int] = field(default_factory=dict)
    model_loaded: bool = False
    capture_mode: str = "live"                        # "live" | "replay"
    interface: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
