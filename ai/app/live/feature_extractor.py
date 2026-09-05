"""Convert live flows into the dataframe shape expected by TemporalGraphBuilder."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

import pandas as pd

from app.live.flow_processor import FlowRecord


def flows_to_dataframe(
    flows: Iterable[FlowRecord],
    dns_lookup: dict[str, str] | None = None,
) -> pd.DataFrame:
    """Build a preprocessing-compatible flow table (same columns as dataset loader)."""
    rows: list[dict] = []
    dns_lookup = dns_lookup or {}

    for f in flows:
        ts = f.last_seen or f.first_seen or datetime.now(timezone.utc)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        hostname = f.dns_name or dns_lookup.get(f.dst_ip) or dns_lookup.get(f.src_ip)
        rows.append({
            "timestamp": ts,
            "src_ip": f.src_ip,
            "dst_ip": f.dst_ip,
            "src_port": int(f.src_port),
            "dst_port": int(f.dst_port),
            "protocol": (f.protocol or "tcp").lower(),
            "src_packets": int(f.src_packets) or 1,
            "dst_packets": int(f.dst_packets) or 0,
            "src_bytes": int(f.src_bytes),
            "dst_bytes": int(f.dst_bytes),
            "duration": float(f.duration),
            "hostname": hostname,
            # Metadata only — never used as a model input feature.
            "tcp_flags": int(f.tcp_flags or 0),
        })

    if not rows:
        return pd.DataFrame(columns=[
            "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
            "src_packets", "dst_packets", "src_bytes", "dst_bytes", "duration",
            "hostname", "tcp_flags",
        ])

    return pd.DataFrame(rows)
