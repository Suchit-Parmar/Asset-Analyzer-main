"""Live packet capture — authorized local interface only (defensive monitoring)."""

from __future__ import annotations

import logging
import re
import socket
import threading
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

logger = logging.getLogger(__name__)

# Bound memory: keep a rolling buffer of recent raw packet summaries (no payloads).
_MAX_PACKET_BUFFER = 50_000

# Reject shell / path metacharacters in interface names (never shell out).
_UNSAFE_IFACE_CHARS = re.compile(r"[;|&$`<>\n\r\"'\\]")


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
    tcp_flags: int | None = None  # raw TCP flags byte when available


def _is_ipv4_family(family: Any) -> bool:
    if family == socket.AF_INET:
        return True
    try:
        if int(family) == int(socket.AF_INET):
            return True
    except (TypeError, ValueError):
        pass
    return str(family).endswith("AF_INET") and "AF_INET6" not in str(family)


def list_interfaces() -> list[dict[str, Any]]:
    """Return real local NICs available for capture (no fabricated names).

    Uses psutil only. Scapy's Windows NIC enumerator is intentionally avoided here
    because it can block under Npcap contention and stall interface APIs/tests.
    """
    interfaces: list[dict[str, Any]] = []
    try:
        import psutil

        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for name, addr_list in addrs.items():
            ipv4 = next(
                (
                    a.address
                    for a in addr_list
                    if _is_ipv4_family(getattr(a, "family", None))
                    and a.address
                    and not str(a.address).startswith("127.")
                ),
                None,
            )
            if ipv4 is None:
                ipv4 = next(
                    (
                        a.address
                        for a in addr_list
                        if _is_ipv4_family(getattr(a, "family", None))
                    ),
                    None,
                )
            st = stats.get(name)
            interfaces.append({
                "name": name,
                "display_name": name,
                "ipv4": ipv4,
                "is_up": bool(st.isup) if st else False,
                "speed_mbps": int(st.speed) if st and st.speed else None,
            })
    except Exception as exc:
        logger.warning("psutil interface list failed: %s", exc)

    def _rank(i: dict[str, Any]) -> tuple:
        name = str(i.get("name") or "")
        name_l = f"{name} {i.get('display_name') or ''}".lower()
        ipv4 = str(i.get("ipv4") or "")
        loopback = ipv4.startswith("127.") or "loopback" in name_l
        # Without Scapy descriptions, Host-Only NICs often appear as "Ethernet N"
        # on 192.168.56.0/24 (VirtualBox default) — treat as virtual.
        virtual = any(
            k in name_l
            for k in (
                "virtualbox", "vmware", "hyper-v", "vbox", "virtual",
                "teredo", "bluetooth", "wi-fi direct", "vpn", "host-only",
            )
        ) or ipv4.startswith("192.168.56.")
        # Prefer common primary NIC names for default dropdown selection.
        primary = name_l.strip() in ("wi-fi", "wifi", "wlan", "ethernet", "eth0", "en0")
        return (
            not bool(i.get("is_up")),
            ipv4 == "" or ipv4.startswith("169.254."),
            loopback,
            virtual,
            not primary,
            name,
        )

    interfaces.sort(key=_rank)
    return interfaces


def validate_interface_name(iface: str) -> str:
    """Server-side validation: known NIC only, no shell metacharacters."""
    name = (iface or "").strip()
    if not name:
        raise ValueError("interface is required")
    if len(name) > 256:
        raise ValueError("interface name too long")
    if _UNSAFE_IFACE_CHARS.search(name):
        raise ValueError("Invalid interface name")
    # Disallow path traversal / absolute paths disguised as iface names.
    if "/" in name or "\\" in name or ".." in name:
        raise ValueError("Invalid interface name")

    known = {str(i["name"]) for i in list_interfaces()}
    if name not in known:
        raise ValueError(f"Unknown or unavailable interface: {name}")
    return name


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
        self._dns_cache.clear()
        with self._lock:
            self._buffer.clear()

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
                tcp_flags: int | None = None
                if pkt.haslayer(TCP):
                    proto = "tcp"
                    sport = int(pkt[TCP].sport)
                    dport = int(pkt[TCP].dport)
                    try:
                        tcp_flags = int(pkt[TCP].flags)
                    except Exception:
                        tcp_flags = None
                elif pkt.haslayer(UDP):
                    proto = "udp"
                    sport = int(pkt[UDP].sport)
                    dport = int(pkt[UDP].dport)
                elif pkt.haslayer(IP) and int(getattr(pkt[IP], "proto", 0) or 0) == 1:
                    proto = "icmp"

                dns_name = None
                if pkt.haslayer(DNS):
                    dns = pkt[DNS]
                    # Passively observe DNS answers only (no active queries).
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
                    tcp_flags=tcp_flags,
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
            # Always bind to a concrete validated interface name (no "any" fake).
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
