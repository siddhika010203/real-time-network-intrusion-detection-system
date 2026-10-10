"""
Turn a stream of packets into per-source behavioural summaries.

Both detectors read the same FlowFeatures object, so a rule and a model can
never disagree about what the traffic looked like - only about what it means.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from typing import Dict, Iterable, List

from .schema import FlowFeatures, PacketRecord


class _SourceAccumulator:
    """Running totals for one source IP inside one window."""

    __slots__ = ("packets", "bytes", "dst_ports", "dst_ips", "port_hits",
                 "syn", "rst", "proto", "auth_hits", "first_ts", "last_ts")

    def __init__(self) -> None:
        self.packets = 0
        self.bytes = 0
        self.dst_ports: set[int] = set()
        self.dst_ips: set[str] = set()
        self.port_hits: Counter = Counter()
        self.syn = 0
        self.rst = 0
        self.proto: Counter = Counter()
        self.auth_hits: Counter = Counter()
        self.first_ts = 0.0
        self.last_ts = 0.0

    def add(self, pkt: PacketRecord, auth_ports: Iterable[int]) -> None:
        if self.packets == 0:
            self.first_ts = pkt.ts
        self.last_ts = pkt.ts

        self.packets += 1
        self.bytes += pkt.length
        self.proto[pkt.protocol] += 1
        self.dst_ips.add(pkt.dst_ip)

        if pkt.dst_port:
            self.dst_ports.add(pkt.dst_port)
            self.port_hits[pkt.dst_port] += 1
            if pkt.dst_port in auth_ports and pkt.is_syn_only:
                self.auth_hits[pkt.dst_port] += 1

        if pkt.protocol == "TCP":
            if pkt.is_syn_only:
                self.syn += 1
            if "R" in pkt.tcp_flags:
                self.rst += 1


def _entropy(counter: Counter) -> float:
    """
    Shannon entropy over destination ports.

    A normal client hammers a couple of ports, so entropy stays low. A scanner
    spreads evenly across many ports, so entropy climbs. This separates the two
    better than a raw port count when a scan is slow.
    """
    total = sum(counter.values())
    if total <= 1:
        return 0.0
    h = 0.0
    for count in counter.values():
        p = count / total
        h -= p * math.log2(p)
    return h


class WindowAggregator:
    """
    Collects packets, then hands back one FlowFeatures per active source when
    the window closes. Stateless between windows by design: it keeps memory
    flat under a flood instead of growing with attacker-controlled input.
    """

    def __init__(self, window_seconds: float, auth_ports: Iterable[int] = ()):
        self.window_seconds = window_seconds
        self.auth_ports = set(auth_ports)
        self._sources: Dict[str, _SourceAccumulator] = defaultdict(_SourceAccumulator)
        self._window_start = 0.0
        self._total_bytes = 0
        self._total_packets = 0
        self._proto_mix: Counter = Counter()

    # -- ingest ----------------------------------------------------------

    def add(self, pkt: PacketRecord) -> None:
        if self._window_start == 0.0:
            self._window_start = pkt.ts
        self._sources[pkt.src_ip].add(pkt, self.auth_ports)
        self._total_packets += 1
        self._total_bytes += pkt.length
        self._proto_mix[pkt.protocol] += 1

    def is_due(self, now: float) -> bool:
        return (
            self._window_start > 0.0
            and (now - self._window_start) >= self.window_seconds
        )

    # -- read-only view for the stats frame ------------------------------

    @property
    def total_packets(self) -> int:
        return self._total_packets

    @property
    def protocol_mix(self) -> Dict[str, int]:
        return dict(self._proto_mix)

    def top_talkers(self, n: int = 5) -> List[dict]:
        ranked = sorted(
            self._sources.items(), key=lambda kv: kv[1].packets, reverse=True
        )[:n]
        return [
            {"ip": ip, "packets": acc.packets, "bytes": acc.bytes}
            for ip, acc in ranked
        ]

    # -- close the window ------------------------------------------------

    def flush(self, now: float) -> List[FlowFeatures]:
        """Emit one FlowFeatures per source, then reset for the next window."""
        start = self._window_start or now
        duration = max(now - start, 0.001)
        out: List[FlowFeatures] = []

        for ip, acc in self._sources.items():
            if acc.packets == 0:
                continue
            tcp = acc.proto.get("TCP", 0)
            udp = acc.proto.get("UDP", 0)
            icmp = acc.proto.get("ICMP", 0)

            out.append(
                FlowFeatures(
                    src_ip=ip,
                    window_start=start,
                    window_end=now,
                    packet_count=acc.packets,
                    byte_count=acc.bytes,
                    mean_packet_size=acc.bytes / acc.packets,
                    distinct_dst_ports=len(acc.dst_ports),
                    distinct_dst_ips=len(acc.dst_ips),
                    syn_count=acc.syn,
                    syn_ratio=acc.syn / acc.packets,
                    rst_count=acc.rst,
                    tcp_ratio=tcp / acc.packets,
                    udp_ratio=udp / acc.packets,
                    icmp_ratio=icmp / acc.packets,
                    packets_per_sec=acc.packets / duration,
                    bytes_per_sec=acc.bytes / duration,
                    port_entropy=_entropy(acc.port_hits),
                )
            )

        # The rule engine needs raw auth-port counts, which are not part of the
        # ML feature vector. Attach them as a side channel keyed by source.
        self.last_auth_hits = {
            ip: dict(acc.auth_hits) for ip, acc in self._sources.items() if acc.auth_hits
        }

        self._sources.clear()
        self._proto_mix.clear()
        self._window_start = now
        self._total_bytes = 0
        return out
