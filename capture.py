"""
Packet capture.

Two sources, one output. Both push PacketRecord objects onto a queue so the
detection engine never learns whether traffic is live or replayed:

  LiveCapture   - Scapy sniffing a real interface. Needs root/admin.
  ReplayCapture - the same pipeline fed from a .pcap file. This is the
                  demo fallback for machines where you cannot get root.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from typing import Optional

from scapy.all import sniff, PcapReader  # type: ignore
from scapy.layers.inet import IP, TCP, UDP, ICMP  # type: ignore
from scapy.layers.inet6 import IPv6  # type: ignore

from .schema import PacketRecord

log = logging.getLogger("nids.capture")


def packet_to_record(pkt) -> Optional[PacketRecord]:
    """Flatten a Scapy packet into a PacketRecord, or None if uninteresting."""
    if IP in pkt:
        ip = pkt[IP]
        src, dst = ip.src, ip.dst
    elif IPv6 in pkt:
        ip = pkt[IPv6]
        src, dst = ip.src, ip.dst
    else:
        return None

    protocol = "OTHER"
    src_port = dst_port = 0
    flags = ""

    if TCP in pkt:
        protocol = "TCP"
        tcp = pkt[TCP]
        src_port, dst_port = int(tcp.sport), int(tcp.dport)
        flags = str(tcp.flags)
    elif UDP in pkt:
        protocol = "UDP"
        udp = pkt[UDP]
        src_port, dst_port = int(udp.sport), int(udp.dport)
    elif ICMP in pkt:
        protocol = "ICMP"

    return PacketRecord(
        ts=float(pkt.time),
        src_ip=src,
        dst_ip=dst,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        length=len(pkt),
        tcp_flags=flags,
    )


class _BaseCapture(threading.Thread):
    def __init__(self, out_queue: "queue.Queue[PacketRecord]"):
        super().__init__(daemon=True, name=self.__class__.__name__)
        self.out_queue = out_queue
        self._stop_event = threading.Event()
        self.dropped = 0
        self.captured = 0

    def stop(self) -> None:
        self._stop_event.set()

    def _emit(self, pkt) -> None:
        record = packet_to_record(pkt)
        if record is None:
            return
        try:
            self.out_queue.put_nowait(record)
            self.captured += 1
        except queue.Full:
            # Drop rather than block the capture thread. A blocked sniffer
            # loses packets at the kernel buffer instead, which is worse
            # because you cannot see it happening.
            self.dropped += 1
            if self.dropped % 1000 == 1:
                log.warning("queue full, dropped %d packets", self.dropped)


class LiveCapture(_BaseCapture):
    """Sniff a real interface. Requires root on Linux, admin + Npcap on Windows."""

    mode = "live"

    def __init__(self, out_queue, interface: str | None = None,
                 bpf_filter: str = "ip"):
        super().__init__(out_queue)
        self.interface = interface
        self.bpf_filter = bpf_filter

    def run(self) -> None:
        log.info("live capture starting on %s (filter=%r)",
                 self.interface or "default interface", self.bpf_filter)
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._emit,
                store=False,
                stop_filter=lambda _p: self._stop_event.is_set(),
            )
        except PermissionError:
            log.error(
                "permission denied opening the interface. Run with sudo, or "
                "use replay mode: NIDS_PCAP=data/sample.pcap python run.py"
            )
        except OSError as exc:
            log.error("capture failed: %s", exc)


class ReplayCapture(_BaseCapture):
    """
    Feed the pipeline from a .pcap file, honouring the original inter-packet
    timing so the dashboard behaves exactly as it does on live traffic.

    Timestamps are rewritten to 'now' so the windowing logic and the dashboard
    clock agree.
    """

    mode = "replay"

    def __init__(self, out_queue, pcap_file: str, speed: float = 1.0,
                 loop: bool = True):
        super().__init__(out_queue)
        self.pcap_file = pcap_file
        self.speed = max(speed, 0.01)
        self.loop = loop

    def run(self) -> None:
        log.info("replaying %s at %.1fx", self.pcap_file, self.speed)
        while not self._stop_event.is_set():
            first_pcap_ts: float | None = None
            wall_start = time.time()
            try:
                with PcapReader(self.pcap_file) as reader:
                    for pkt in reader:
                        if self._stop_event.is_set():
                            return
                        if first_pcap_ts is None:
                            first_pcap_ts = float(pkt.time)

                        offset = (float(pkt.time) - first_pcap_ts) / self.speed
                        sleep_for = (wall_start + offset) - time.time()
                        if sleep_for > 0:
                            time.sleep(min(sleep_for, 1.0))

                        record = packet_to_record(pkt)
                        if record is None:
                            continue
                        record.ts = time.time()   # move into the present
                        try:
                            self.out_queue.put_nowait(record)
                            self.captured += 1
                        except queue.Full:
                            self.dropped += 1
            except FileNotFoundError:
                log.error("pcap not found: %s", self.pcap_file)
                return
            if not self.loop:
                return
            log.info("replay reached end of file, looping")


def build_capture(cfg, out_queue) -> _BaseCapture:
    """Pick the capture source from config. Replay wins if a pcap is set."""
    if cfg.pcap_file:
        return ReplayCapture(out_queue, cfg.pcap_file, cfg.replay_speed)
    return LiveCapture(out_queue, cfg.interface, cfg.bpf_filter)
