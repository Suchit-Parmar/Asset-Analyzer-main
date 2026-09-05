"""Aggregate live packets into bidirectional flow records."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable

from app.live.capture import PacketEvent


@dataclass
class FlowRecord:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    src_packets: int = 0
    dst_packets: int = 0
    src_bytes: int = 0
    dst_bytes: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    dns_name: str | None = None
    tcp_flags: int = 0  # bitwise OR of observed TCP flags (metadata only)

    @property
    def duration(self) -> float:
        if not self.first_seen or not self.last_seen:
            return 0.0
        return max(0.0, (self.last_seen - self.first_seen).total_seconds())

    @property
    def packet_count(self) -> int:
        return self.src_packets + self.dst_packets

    @property
    def byte_count(self) -> int:
        return self.src_bytes + self.dst_bytes


@dataclass
class FlowAggregator:
    """In-window flow table keyed by 5-tuple (direction-normalized)."""

    flows: dict[tuple, FlowRecord] = field(default_factory=dict)

    @staticmethod
    def _key(ev: PacketEvent) -> tuple:
        # Normalize direction so A→B and B→A merge into one flow.
        a = (ev.src_ip, ev.src_port)
        b = (ev.dst_ip, ev.dst_port)
        if a <= b:
            return (ev.src_ip, ev.dst_ip, ev.src_port, ev.dst_port, ev.protocol)
        return (ev.dst_ip, ev.src_ip, ev.dst_port, ev.src_port, ev.protocol)

    def ingest(self, events: Iterable[PacketEvent]) -> None:
        for ev in events:
            key = self._key(ev)
            flow = self.flows.get(key)
            if flow is None:
                # Store canonical orientation from key
                src_ip, dst_ip, sport, dport, proto = key
                flow = FlowRecord(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=int(sport),
                    dst_port=int(dport),
                    protocol=proto,
                )
                self.flows[key] = flow

            if flow.first_seen is None or ev.timestamp < flow.first_seen:
                flow.first_seen = ev.timestamp
            if flow.last_seen is None or ev.timestamp > flow.last_seen:
                flow.last_seen = ev.timestamp

            if ev.src_ip == flow.src_ip and ev.src_port == flow.src_port:
                flow.src_packets += 1
                flow.src_bytes += max(0, int(ev.length))
            else:
                flow.dst_packets += 1
                flow.dst_bytes += max(0, int(ev.length))

            if ev.dns_name and not flow.dns_name:
                flow.dns_name = ev.dns_name
            if ev.tcp_flags is not None:
                flow.tcp_flags |= int(ev.tcp_flags)

    def flush(self) -> list[FlowRecord]:
        out = list(self.flows.values())
        self.flows.clear()
        return out

    def stats(self) -> dict:
        return {
            "active_flows": len(self.flows),
            "packets": sum(f.packet_count for f in self.flows.values()),
            "bytes": sum(f.byte_count for f in self.flows.values()),
        }
