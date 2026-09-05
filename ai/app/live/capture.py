"""Live packet capture — authorized local interface only (defensive monitoring)."""

from __future__ import annotations

import logging
import socket
import threading
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

logger = logging.getLogger(__name__)

# Bound memory: keep a rolling buffer of recent raw packet summaries.
_MAX_PACKET_BUFFER = 50_000


@dataclass
class PacketEvent:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    length: int
    dns_name: str | None = None


def list_interfaces() -> list[dict[str, Any]]:
    """Return authorized local NICs available for capture."""
    interfaces: list[dict[str, Any]] = []
    try:
        import psutil

        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for name, addr_list in addrs.items():
            ipv4 = next((a.address for a in addr_list if getattr(a, "family", None) == socket.AF_INET), None)
            st = stats.get(name)
            interfaces.append({
                "name": name,
                "display_name": name,
                "ipv4": ipv4,
                "is_up": bool(st.isup) if st else True,
                "speed_mbps": int(st.speed) if st and st.speed else None,
            })
    except Exception as exc:
        logger.warning("psutil interface list failed: %s", exc)

    if not interfaces:
        # Minimal fallback so the UI can still show an option.
        interfaces.append({
            "name": "any",
            "display_name": "Default (any)",
            "ipv4": None,
            "is_up": True,
            "speed_mbps": None,
        })
    return interfaces


class LiveCapture:
    """Background Scapy sniffer for a single authorized interface."""

    def __init__(self, on_packet: Callable[[PacketEvent], None] | None = None):
        self._on_packet = on_packet
        self._sniffer = None
        self._iface: str | None = None
        self._running = False
        self._lock = threading.Lock()
        self._buffer: deque[PacketEvent] = deque(maxlen=_MAX_PACKET_BUFFER)
        self._packet_count = 0
        self._error: str | None = None
        self._dns_cache: dict[str, str] = {}

    @property
    def running(self) -> bool:
        return self._running

    @property
    def interface(self) -> str | None:
        return self._iface

    @property
    def packet_count(self) -> int:
        return self._packet_count

    @property
    def last_error(self) -> str | None:
        return self._error

    def drain(self) -> list[PacketEvent]:
        with self._lock:
            items = list(self._buffer)
            self._buffer.clear()
            return items

    def peek_dns(self, ip: str) -> str | None:
        return self._dns_cache.get(ip)

    def start(self, iface: str) -> None:
        if self._running:
            raise RuntimeError("Capture already running — stop it first")

        try:
            from scapy.all import AsyncSniffer, DNS, IP, IPv6, TCP, UDP  # type: ignore
        except Exception as exc:
            self._error = (
                "Live capture unavailable: Scapy is not usable in this environment. "
                f"({exc})"
            )
            raise PermissionError(self._error) from exc

        self._error = None
        self._iface = iface
        self._packet_count = 0

        def _handle(pkt) -> None:  # noqa: ANN001
            try:
                ts = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc)
                src_ip = dst_ip = None
                if pkt.haslayer(IP):
                    src_ip = str(pkt[IP].src)
                    dst_ip = str(pkt[IP].dst)
                elif pkt.haslayer(IPv6):
                    src_ip = str(pkt[IPv6].src)
                    dst_ip = str(pkt[IPv6].dst)
                else:
                    return

                proto = "other"
                sport = dport = 0
                if pkt.haslayer(TCP):
                    proto = "tcp"
                    sport = int(pkt[TCP].sport)
                    dport = int(pkt[TCP].dport)
                elif pkt.haslayer(UDP):
                    proto = "udp"
                    sport = int(pkt[UDP].sport)
                    dport = int(pkt[UDP].dport)
                elif pkt.haslayer(IP) and int(getattr(pkt[IP], "proto", 0) or 0) == 1:
                    proto = "icmp"

                dns_name = None
                if pkt.haslayer(DNS):
                    dns = pkt[DNS]
                    # Passiveively observe DNS answers only (no active queries).
                    if getattr(dns, "an", None) is not None:
                        try:
                            for i in range(int(dns.ancount or 0)):
                                rr = dns.an[i]
                                rdata = getattr(rr, "rdata", None)
                                rrname = getattr(rr, "rrname", b"")
                                if isinstance(rrname, bytes):
                                    rrname = rrname.decode("utf-8", errors="ignore")
                                name = str(rrname).rstrip(".")
                                if rdata is not None and name:
                                    ip_str = str(rdata)
                                    if ip_str.count(".") == 3 or ":" in ip_str:
                                        self._dns_cache[ip_str] = name
                                        if ip_str in (src_ip, dst_ip):
                                            dns_name = name
                        except Exception:
                            pass

                length = int(len(pkt))
                event = PacketEvent(
                    timestamp=ts,
                    src_ip=src_ip or "0.0.0.0",
                    dst_ip=dst_ip or "0.0.0.0",
                    src_port=sport,
                    dst_port=dport,
                    protocol=proto,
                    length=length,
                    dns_name=dns_name,
                )
                with self._lock:
                    self._buffer.append(event)
                    self._packet_count += 1
                if self._on_packet:
                    self._on_packet(event)
            except Exception as exc:
                logger.debug("packet parse skipped: %s", exc)

        try:
            kwargs: dict[str, Any] = {
                "prn": _handle,
                "store": False,
            }
            if iface and iface.lower() not in ("any", "default"):
                kwargs["iface"] = iface
            self._sniffer = AsyncSniffer(**kwargs)
            self._sniffer.start()
            self._running = True
            logger.info("Live capture started on iface=%s", iface)
        except PermissionError as exc:
            self._error = (
                "Live Detection Unavailable. Network capture permission is required. "
                "Please run with authorized network-capture permissions (e.g. Administrator / Npcap)."
            )
            raise PermissionError(self._error) from exc
        except OSError as exc:
            self._error = f"Interface unavailable or capture failed: {exc}"
            raise RuntimeError(self._error) from exc
        except Exception as exc:
            msg = str(exc).lower()
            if "permission" in msg or "access" in msg or "npcap" in msg or "winpcap" in msg:
                self._error = (
                    "Live Detection Unavailable. Network capture permission is required. "
                    "Please run with authorized network-capture permissions (e.g. Administrator / Npcap)."
                )
                raise PermissionError(self._error) from exc
            self._error = f"Capture failed: {exc}"
            raise RuntimeError(self._error) from exc

    def stop(self) -> None:
        sniffer = self._sniffer
        self._sniffer = None
        self._running = False
        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception as exc:
                logger.warning("sniffer stop: %s", exc)
        logger.info("Live capture stopped (packets=%s)", self._packet_count)
