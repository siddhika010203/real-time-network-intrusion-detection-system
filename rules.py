"""
Rule-based detection.

Each rule is a small function over one FlowFeatures window. They cover the
attacks whose signatures are unambiguous, which keeps the ML layer free to
handle the things a threshold cannot express.

Every rule returns an Alert or None. Adding a rule means writing one function
and appending it to RULES - nothing else changes.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional

from .schema import Alert, FlowFeatures

Rule = Callable[[FlowFeatures, object, Dict[int, int]], Optional[Alert]]


# --------------------------------------------------------------------------
# Individual rules
# --------------------------------------------------------------------------

def port_scan(f: FlowFeatures, cfg, auth_hits) -> Optional[Alert]:
    """One source touching many distinct ports on few hosts: vertical scan."""
    if f.distinct_dst_ports < cfg.port_scan_ports:
        return None

    # High entropy means the ports were spread evenly rather than one service
    # being retried. Both patterns hit the count threshold; only one is a scan.
    if f.port_entropy < 3.0:
        return None

    severity = "high" if f.distinct_dst_ports > cfg.port_scan_ports * 5 else "medium"
    return Alert(
        threat_type="port_scan",
        src_ip=f.src_ip,
        severity=severity,
        detector="rule",
        description=(
            f"{f.src_ip} probed {f.distinct_dst_ports} distinct ports across "
            f"{f.distinct_dst_ips} host(s) in this window."
        ),
        evidence={
            "distinct_dst_ports": f.distinct_dst_ports,
            "distinct_dst_ips": f.distinct_dst_ips,
            "port_entropy": round(f.port_entropy, 2),
            "syn_ratio": round(f.syn_ratio, 2),
        },
    )


def host_sweep(f: FlowFeatures, cfg, auth_hits) -> Optional[Alert]:
    """One source touching few ports on many hosts: horizontal sweep."""
    if f.distinct_dst_ips < cfg.host_sweep_hosts or f.distinct_dst_ports > 3:
        return None
    return Alert(
        threat_type="host_sweep",
        src_ip=f.src_ip,
        severity="medium",
        detector="rule",
        description=(
            f"{f.src_ip} contacted {f.distinct_dst_ips} hosts on "
            f"{f.distinct_dst_ports} port(s) - looks like host discovery."
        ),
        evidence={
            "distinct_dst_ips": f.distinct_dst_ips,
            "distinct_dst_ports": f.distinct_dst_ports,
            "icmp_ratio": round(f.icmp_ratio, 2),
        },
    )


def syn_flood(f: FlowFeatures, cfg, auth_hits) -> Optional[Alert]:
    """Many half-open handshakes and almost nothing completing."""
    if f.syn_count < cfg.syn_flood_count or f.syn_ratio < cfg.syn_flood_ratio:
        return None

    # A fast port scan is also thousands of bare SYNs, so raw SYN count alone
    # reports one event twice. A flood concentrates on a service; a scan
    # spreads across ports. Concentration is what separates them.
    if f.distinct_dst_ports > 5 or f.port_entropy > 2.0:
        return None
    return Alert(
        threat_type="syn_flood",
        src_ip=f.src_ip,
        severity="critical",
        detector="rule",
        description=(
            f"{f.src_ip} sent {f.syn_count} SYN packets "
            f"({f.syn_ratio:.0%} of its traffic) without completing handshakes."
        ),
        evidence={
            "syn_count": f.syn_count,
            "syn_ratio": round(f.syn_ratio, 2),
            "packets_per_sec": round(f.packets_per_sec, 1),
        },
    )


def volumetric_flood(f: FlowFeatures, cfg, auth_hits) -> Optional[Alert]:
    """Raw packet or byte rate from a single source far above normal."""
    if f.packets_per_sec < cfg.dos_pps and f.bytes_per_sec < cfg.dos_bps:
        return None

    # Defer to syn_flood when the traffic is overwhelmingly half-open
    # handshakes - that rule describes the same event more precisely.
    if f.syn_ratio >= cfg.syn_flood_ratio and f.distinct_dst_ports <= 5:
        return None

    return Alert(
        threat_type="volumetric_flood",
        src_ip=f.src_ip,
        severity="high",
        detector="rule",
        description=(
            f"{f.src_ip} sustained {f.packets_per_sec:.0f} packets/s "
            f"({f.bytes_per_sec / 1e6:.1f} MB/s) to {f.distinct_dst_ips} host(s)."
        ),
        evidence={
            "packets_per_sec": round(f.packets_per_sec, 1),
            "bytes_per_sec": round(f.bytes_per_sec, 1),
            "mean_packet_size": round(f.mean_packet_size, 1),
        },
    )


def brute_force(f: FlowFeatures, cfg, auth_hits) -> Optional[Alert]:
    """Repeated connection attempts against a single authentication service."""
    if not auth_hits:
        return None
    port, attempts = max(auth_hits.items(), key=lambda kv: kv[1])
    if attempts < cfg.brute_force_attempts:
        return None

    service = {
        21: "FTP", 22: "SSH", 23: "Telnet", 3389: "RDP",
        3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 5900: "VNC",
    }.get(port, f"port {port}")

    return Alert(
        threat_type="brute_force",
        src_ip=f.src_ip,
        severity="high",
        detector="rule",
        description=(
            f"{f.src_ip} opened {attempts} connections to {service} "
            f"in this window - consistent with credential guessing."
        ),
        evidence={"service": service, "port": port, "attempts": attempts},
    )


def icmp_flood(f: FlowFeatures, cfg, auth_hits) -> Optional[Alert]:
    """Almost pure ICMP at high rate: ping flood."""
    if f.icmp_ratio < 0.9 or f.packets_per_sec < cfg.dos_pps / 4:
        return None
    return Alert(
        threat_type="icmp_flood",
        src_ip=f.src_ip,
        severity="medium",
        detector="rule",
        description=(
            f"{f.src_ip} sent {f.packet_count} ICMP packets at "
            f"{f.packets_per_sec:.0f}/s."
        ),
        evidence={
            "icmp_ratio": round(f.icmp_ratio, 2),
            "packets_per_sec": round(f.packets_per_sec, 1),
        },
    )


RULES: List[Rule] = [
    port_scan,
    host_sweep,
    syn_flood,
    volumetric_flood,
    brute_force,
    icmp_flood,
]


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------

class RuleEngine:
    def __init__(self, cfg):
        self.cfg = cfg
        self.whitelist = set(cfg.whitelist)

    def evaluate(
        self,
        features: FlowFeatures,
        auth_hits: Dict[int, int] | None = None,
    ) -> List[Alert]:
        if features.src_ip in self.whitelist:
            return []
        alerts: List[Alert] = []
        for rule in RULES:
            try:
                alert = rule(features, self.cfg, auth_hits or {})
            except Exception:  # a broken rule must not stop the others
                continue
            if alert is not None:
                alerts.append(alert)
        return alerts
