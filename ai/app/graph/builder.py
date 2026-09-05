"""Graph construction from network traffic data."""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any

import numpy as np
import pandas as pd


PROTOCOL_MAP = {
    "tcp": 0, "udp": 1, "http": 2, "https": 3, "ssh": 4,
    "dns": 5, "ftp": 6, "smtp": 7, "mqtt": 8, "icmp": 9, "other": 10,
}

NODE_TYPE_MAP = {
    "ip_address": 0, "host": 1, "server": 2, "router": 3,
    "switch": 4, "iot_device": 5, "user": 6,
}

NODE_FEATURE_DIM = 16

# Canonical names for the 16-dim endpoint node vector produced by
# ``_extract_node_features`` (dims 0–7 active; 8–15 reserved/zero-filled).
ENDPOINT_FEATURE_NAMES: list[str] = [
    "log_packets",
    "log_bytes",
    "log_connections",
    "log_failed_logins",
    "log_port_count",
    "node_type",
    "log_avg_bytes",
    "conn_ratio",
    "reserved_9",
    "reserved_10",
    "reserved_11",
    "reserved_12",
    "reserved_13",
    "reserved_14",
    "reserved_15",
    "reserved_16",
]

# Indices 8–15 are intentionally zero-padded during training and live inference.
ENDPOINT_RESERVED_INDICES: tuple[int, ...] = tuple(range(8, NODE_FEATURE_DIM))


def endpoint_feature_name(index: int) -> str:
    if 0 <= index < len(ENDPOINT_FEATURE_NAMES):
        return ENDPOINT_FEATURE_NAMES[index]
    return f"feature_{index}"


def is_reserved_endpoint_dim(index: int) -> bool:
    return index in ENDPOINT_RESERVED_INDICES


def _node_id(ip: str) -> str:
    return hashlib.md5(ip.encode()).hexdigest()[:12]


def _infer_node_type(ip: str, ports: list[int]) -> str:
    if ip.endswith(".1") or ip.endswith(".254"):
        return "router"
    if any(p in ports for p in [80, 443, 8080, 5432, 3306]):
        return "server"
    if any(p in ports for p in [1883, 8883, 5683]):
        return "iot_device"
    if ip.startswith("10.") or ip.startswith("192.168."):
        return "host"
    return "ip_address"


def _majority_attack_type(values: list[str]) -> str:
    if not values:
        return "Normal"
    counts = Counter(values)
    non_normal = {k: v for k, v in counts.items() if k != "Normal"}
    if non_normal:
        top_attack, top_count = max(non_normal.items(), key=lambda kv: kv[1])
        if top_count >= max(1, len(values) // 10):
            return top_attack
    return counts.most_common(1)[0][0]


def _graph_metrics(node_ids: list[str], edges: list[dict]) -> dict[str, float]:
    n = len(node_ids)
    if n == 0:
        return {"density": 0.0, "avg_degree": 0.0}
    unique = {(e["source"], e["target"]) for e in edges}
    m = len(unique)
    density = float(m) / float(n * (n - 1)) if n > 1 else 0.0
    degree: dict[str, int] = defaultdict(int)
    for src, dst in unique:
        degree[src] += 1
        degree[dst] += 1
    avg_degree = float(np.mean([degree[nid] for nid in node_ids])) if node_ids else 0.0
    return {"density": density, "avg_degree": avg_degree}


class TemporalGraphBuilder:
    """Build temporal graph snapshots from preprocessed flow records."""

    def __init__(self, window_seconds: int = 30):
        self.window_seconds = window_seconds

    def build_from_dataframe(self, df: pd.DataFrame) -> list[dict[str, Any]]:
        df = self._normalize_columns(df.copy())
        if "timestamp" not in df.columns:
            df["timestamp"] = pd.date_range(start="2017-07-03", periods=len(df), freq="100ms")

        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df = df.sort_values("timestamp").reset_index(drop=True)

        snapshots: list[dict[str, Any]] = []
        start = df["timestamp"].min()
        end = df["timestamp"].max()
        if pd.isna(start) or pd.isna(end):
            return [self.build_single_snapshot(df)]

        current = start
        while current < end:
            window_end = current + timedelta(seconds=self.window_seconds)
            window_df = df[(df["timestamp"] >= current) & (df["timestamp"] < window_end)]
            if len(window_df) > 0:
                snapshots.append(self._build_snapshot(window_df, current))
            current = window_end

        if not snapshots and len(df) > 0:
            ts = start.to_pydatetime() if hasattr(start, "to_pydatetime") else datetime.utcnow()
            snapshots.append(self._build_snapshot(df, ts))

        return snapshots

    def build_single_snapshot(self, df: pd.DataFrame) -> dict[str, Any]:
        df = self._normalize_columns(df.copy())
        return self._build_snapshot(df, datetime.utcnow())

    def _normalize_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        col_map = {
            "srcip": "src_ip", "dstip": "dst_ip", "sport": "src_port", "dport": "dst_port",
            "proto": "protocol", "sttl": "src_ttl", "dttl": "dst_ttl",
            "sbytes": "src_bytes", "dbytes": "dst_bytes", "Spkts": "src_packets",
            "Dpkts": "dst_packets", "dur": "duration",
            "attack_cat": "attack_type", "category": "attack_type",
            "Label": "raw_label",
        }
        df = df.rename(columns={k: v for k, v in col_map.items() if k in df.columns})
        return df

    def _build_snapshot(self, df: pd.DataFrame, timestamp: datetime) -> dict[str, Any]:
        nodes: dict[str, dict] = {}
        edges: list[dict] = []

        attack_votes: list[str] = []
        if "attack_type" in df.columns:
            attack_votes = [str(v) for v in df["attack_type"].tolist()]
        elif "raw_label" in df.columns:
            attack_votes = [str(v) for v in df["raw_label"].tolist()]

        src_ips = df["src_ip"].astype(str).tolist() if "src_ip" in df.columns else ["0.0.0.0"] * len(df)
        dst_ips = df["dst_ip"].astype(str).tolist() if "dst_ip" in df.columns else ["0.0.0.0"] * len(df)
        protocols = (
            df["protocol"].astype(str).str.lower().tolist()
            if "protocol" in df.columns
            else ["tcp"] * len(df)
        )
        src_ports = (
            pd.to_numeric(df["src_port"], errors="coerce").fillna(0).astype(int).tolist()
            if "src_port" in df.columns
            else [0] * len(df)
        )
        dst_ports = (
            pd.to_numeric(df["dst_port"], errors="coerce").fillna(0).astype(int).tolist()
            if "dst_port" in df.columns
            else [0] * len(df)
        )
        src_packets = (
            pd.to_numeric(df["src_packets"], errors="coerce").fillna(1).astype(np.int64).tolist()
            if "src_packets" in df.columns
            else [1] * len(df)
        )
        dst_packets = (
            pd.to_numeric(df["dst_packets"], errors="coerce").fillna(1).astype(np.int64).tolist()
            if "dst_packets" in df.columns
            else [1] * len(df)
        )
        src_bytes = (
            pd.to_numeric(df["src_bytes"], errors="coerce").fillna(0).astype(np.int64).tolist()
            if "src_bytes" in df.columns
            else [0] * len(df)
        )
        dst_bytes = (
            pd.to_numeric(df["dst_bytes"], errors="coerce").fillna(0).astype(np.int64).tolist()
            if "dst_bytes" in df.columns
            else [0] * len(df)
        )
        durations = (
            pd.to_numeric(df["duration"], errors="coerce").fillna(0).astype(float).tolist()
            if "duration" in df.columns
            else [0.0] * len(df)
        )

        ts_iso = timestamp.isoformat() if hasattr(timestamp, "isoformat") else str(timestamp)

        for i in range(len(df)):
            src_ip = src_ips[i]
            dst_ip = dst_ips[i]
            protocol = protocols[i]
            src_port = int(src_ports[i])
            dst_port = int(dst_ports[i])

            for ip, port in [(src_ip, src_port), (dst_ip, dst_port)]:
                nid = _node_id(ip)
                if nid not in nodes:
                    ports = [port] if port else []
                    nodes[nid] = {
                        "id": nid,
                        "ip": ip,
                        "type": _infer_node_type(ip, ports),
                        "packets": 0,
                        "bytes": 0,
                        "connections": 0,
                        "failed_logins": 0,
                        "ports": ports,
                    }
                elif port and port not in nodes[nid]["ports"]:
                    nodes[nid]["ports"].append(port)

            src_id, dst_id = _node_id(src_ip), _node_id(dst_ip)
            nodes[src_id]["packets"] += int(src_packets[i])
            nodes[src_id]["bytes"] += int(src_bytes[i])
            nodes[src_id]["connections"] += 1
            nodes[dst_id]["packets"] += int(dst_packets[i])
            nodes[dst_id]["bytes"] += int(dst_bytes[i])
            nodes[dst_id]["connections"] += 1

            if attack_votes and attack_votes[i] in ("Brute Force", "FTP-Patator", "SSH-Patator"):
                nodes[dst_id]["failed_logins"] += 1

            edges.append({
                "source": src_id,
                "target": dst_id,
                "protocol": protocol,
                "src_port": src_port,
                "dst_port": dst_port,
                "bytes": int(src_bytes[i]) + int(dst_bytes[i]),
                "packets": int(src_packets[i]) + int(dst_packets[i]),
                "duration": float(durations[i]),
                "timestamp": ts_iso,
                "attack_type": attack_votes[i] if attack_votes else "Normal",
            })

        node_ids = list(nodes.keys())
        node_features = self._extract_node_features(nodes)
        edge_index = self._build_edge_index(edges, node_ids)
        majority_attack = _majority_attack_type(attack_votes)
        binary_label = 0 if majority_attack == "Normal" else 1

        return {
            "timestamp": ts_iso,
            "window_seconds": self.window_seconds,
            "nodes": list(nodes.values()),
            "edges": edges,
            "node_features": node_features,
            "edge_index": edge_index,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "attack_type": majority_attack,
            "label": binary_label,
            "graph_metrics": _graph_metrics(node_ids, edges),
        }

    def _extract_node_features(self, nodes: dict[str, dict]) -> list[list[float]]:
        """Build fixed-length 16-dim node feature vectors with log scaling."""
        n_nodes = max(len(nodes), 1)
        features: list[list[float]] = []
        for node in nodes.values():
            packets = float(node["packets"])
            nbytes = float(node["bytes"])
            connections = float(node["connections"])
            failed = float(node["failed_logins"])
            port_count = float(len(node["ports"]))
            node_type = float(NODE_TYPE_MAP.get(node["type"], 1))
            avg_bytes = nbytes / max(packets, 1.0)
            conn_ratio = connections / float(n_nodes)

            vec = [
                float(np.log1p(packets)),
                float(np.log1p(nbytes)),
                float(np.log1p(connections)),
                float(np.log1p(failed)),
                float(np.log1p(port_count)),
                node_type,
                float(np.log1p(avg_bytes)),
                conn_ratio,
                0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            ]
            if len(vec) != NODE_FEATURE_DIM:
                raise ValueError(f"Expected {NODE_FEATURE_DIM}-dim features, got {len(vec)}")
            features.append(vec)
        return features

    def _build_edge_index(self, edges: list[dict], node_ids: list[str]) -> list[list[int]]:
        id_to_idx = {nid: i for i, nid in enumerate(node_ids)}
        edge_index: list[list[int]] = [[], []]
        for edge in edges:
            src = edge["source"]
            dst = edge["target"]
            if src in id_to_idx and dst in id_to_idx:
                edge_index[0].append(id_to_idx[src])
                edge_index[1].append(id_to_idx[dst])
        if not edge_index[0] and node_ids:
            edge_index = [[0], [0]]
        return edge_index
