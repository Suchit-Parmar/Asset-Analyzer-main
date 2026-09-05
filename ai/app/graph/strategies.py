"""Selectable graph construction strategies (Phase 1, Module C).

This module turns graph construction into a first-class, configurable step of the
pipeline. Four research-grade strategies are supported, all producing the *same*
snapshot schema consumed by the training and inference services, so the rest of
the stack (model, checkpoints, dashboards) is unaffected:

  * ``endpoint``   – Endpoint Graph. Nodes are network endpoints (real IPs when
                     available, deterministic endpoint IDs otherwise); edges are
                     communications between them. Directed or undirected.
  * ``flow``       – Flow Graph. Nodes are individual network flows; edges connect
                     temporally/sequentially adjacent flows (configurable distance).
  * ``similarity`` – Feature Similarity Graph. Nodes are flows; edges connect flows
                     whose feature vectors are similar (cosine threshold or kNN).
  * ``temporal``   – Temporal Sliding Window Graph. Endpoint graphs built over
                     sliding time windows with configurable size / overlap / stride.

Every snapshot dict contains at minimum::

    node_features : list[list[float]]   # 16-dim per node
    edge_index    : [[src...], [dst...]]
    node_count, edge_count : int
    attack_type, label     : graph-level majority label
    graph_metrics : {"density", "avg_degree"}
    timestamp     : ISO string
    nodes, edges  : lightweight lists (topology display / explainability)

The model performs graph-level classification (global mean pooling), so any
strategy that yields node features + an edge index is fully compatible.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any

import numpy as np
import pandas as pd

from app.graph.builder import (
    NODE_FEATURE_DIM,
    TemporalGraphBuilder,
    _graph_metrics,
    _majority_attack_type,
)

# Canonical strategy identifiers exposed to the frontend/API.
GRAPH_STRATEGIES = ["endpoint", "flow", "similarity", "temporal"]
DEFAULT_STRATEGY = "temporal"

# Accept legacy / alternate names so old callers and the previous UI keep working.
_STRATEGY_ALIASES = {
    "static": "endpoint",
    "endpoint_graph": "endpoint",
    "endpoint graph": "endpoint",
    "flow_graph": "flow",
    "flow graph": "flow",
    "feature_similarity": "similarity",
    "feature similarity": "similarity",
    "similarity_graph": "similarity",
    "knn": "similarity",
    "sliding_window": "temporal",
    "sliding window": "temporal",
    "temporal_sliding_window": "temporal",
    "tgn": "temporal",
    "continuous": "temporal",
}


def normalize_strategy(strategy: str | None) -> str:
    """Map any accepted alias to a canonical strategy id."""
    key = (strategy or DEFAULT_STRATEGY).strip().lower()
    if key in GRAPH_STRATEGIES:
        return key
    return _STRATEGY_ALIASES.get(key, DEFAULT_STRATEGY)


@dataclass
class GraphConfig:
    """Graph strategy + tunable parameters (serialized into model metadata)."""

    strategy: str = DEFAULT_STRATEGY

    # Endpoint graph
    directed: bool = True

    # Flow graph
    flow_sequential_distance: int = 1

    # Feature similarity graph
    similarity_metric: str = "cosine"  # "cosine" | "knn"
    similarity_threshold: float = 0.8
    similarity_neighbors: int = 5

    # Temporal sliding window graph
    window_size: int = 30  # seconds
    window_overlap: float = 0.0  # 0..1 fraction of the window
    window_stride: int = 0  # seconds; 0 => derived from size & overlap

    # Shared: rows per graph for non-temporal strategies + safety caps
    rows_per_graph: int = 500
    max_flow_nodes: int = 400
    # Scalability cap (Module D): bound the number of snapshots so 250K–1M+ row
    # datasets stay within memory. Chunk size auto-grows to cover all rows while
    # keeping the snapshot count under this ceiling.
    max_snapshots: int = 5000

    # Phase 3: Model Studio feature toggles (timestamp, packet_size, …)
    feature_set: dict[str, bool] | None = None

    @classmethod
    def from_dict(
        cls,
        strategy: str | None = None,
        params: dict[str, Any] | None = None,
    ) -> "GraphConfig":
        """Build a config from a strategy name + loose params dict (API friendly)."""
        params = dict(params or {})
        cfg = cls(strategy=normalize_strategy(strategy or params.get("strategy")))
        for field_name in (
            "directed",
            "flow_sequential_distance",
            "similarity_metric",
            "similarity_threshold",
            "similarity_neighbors",
            "window_size",
            "window_overlap",
            "window_stride",
            "rows_per_graph",
            "max_flow_nodes",
        ):
            if field_name in params and params[field_name] is not None:
                setattr(cfg, field_name, params[field_name])
        # Coerce numeric types defensively (JSON may deliver strings).
        cfg.flow_sequential_distance = max(1, int(cfg.flow_sequential_distance))
        cfg.similarity_threshold = float(cfg.similarity_threshold)
        cfg.similarity_neighbors = max(1, int(cfg.similarity_neighbors))
        cfg.window_size = max(1, int(cfg.window_size))
        cfg.window_overlap = min(max(float(cfg.window_overlap), 0.0), 0.95)
        cfg.window_stride = max(0, int(cfg.window_stride))
        cfg.rows_per_graph = max(10, int(cfg.rows_per_graph))
        cfg.max_flow_nodes = max(10, int(cfg.max_flow_nodes))
        cfg.max_snapshots = max(1, int(cfg.max_snapshots))
        cfg.directed = bool(cfg.directed)
        if "feature_set" in params and params["feature_set"] is not None:
            from app.services.feature_selection import normalize_feature_set

            cfg.feature_set = normalize_feature_set(params["feature_set"])
        return cfg

    def to_metadata(self) -> dict[str, Any]:
        """Compact, strategy-relevant parameters for model metadata / export."""
        base: dict[str, Any] = {"strategy": self.strategy}
        if self.strategy == "endpoint":
            base["directed"] = self.directed
            base["rows_per_graph"] = self.rows_per_graph
        elif self.strategy == "flow":
            base["flow_sequential_distance"] = self.flow_sequential_distance
            base["rows_per_graph"] = self.rows_per_graph
        elif self.strategy == "similarity":
            base["similarity_metric"] = self.similarity_metric
            base["similarity_threshold"] = self.similarity_threshold
            base["similarity_neighbors"] = self.similarity_neighbors
            base["rows_per_graph"] = self.rows_per_graph
        else:  # temporal
            base["window_size"] = self.window_size
            base["window_overlap"] = self.window_overlap
            base["window_stride"] = self.effective_stride()
        if self.feature_set:
            base["feature_set"] = self.feature_set
        return base

    def effective_stride(self) -> int:
        """Temporal stride in seconds (explicit stride wins, else derived from overlap)."""
        if self.window_stride > 0:
            return self.window_stride
        derived = int(round(self.window_size * (1.0 - self.window_overlap)))
        return max(1, derived)


# ---------------------------------------------------------------------------
# Per-flow node features (used by flow + similarity strategies)
# ---------------------------------------------------------------------------

_FLOW_NUMERIC_COLUMNS = [
    "duration",
    "src_bytes",
    "dst_bytes",
    "src_packets",
    "dst_packets",
    "dst_port",
]


def _flow_feature_matrix(df: pd.DataFrame) -> np.ndarray:
    """Build a (rows, NODE_FEATURE_DIM) matrix of per-flow features (log-scaled)."""
    n = len(df)

    def _col(name: str, default: float = 0.0) -> np.ndarray:
        if name in df.columns:
            return pd.to_numeric(df[name], errors="coerce").fillna(default).to_numpy(dtype=float)
        return np.full(n, default, dtype=float)

    duration = _col("duration")
    src_bytes = _col("src_bytes")
    dst_bytes = _col("dst_bytes")
    src_packets = _col("src_packets", 1.0)
    dst_packets = _col("dst_packets", 1.0)
    dst_port = _col("dst_port")

    total_bytes = src_bytes + dst_bytes
    total_packets = src_packets + dst_packets
    avg_bytes = total_bytes / np.maximum(total_packets, 1.0)
    byte_ratio = src_bytes / np.maximum(dst_bytes, 1.0)
    pkt_ratio = src_packets / np.maximum(dst_packets, 1.0)

    if "protocol" in df.columns:
        proto = df["protocol"].astype(str).str.lower()
        proto_code = proto.map({"tcp": 0.0, "udp": 1.0, "icmp": 2.0}).fillna(3.0).to_numpy(dtype=float)
    else:
        proto_code = np.zeros(n, dtype=float)

    cols = [
        np.log1p(np.abs(duration)),
        np.log1p(src_bytes),
        np.log1p(dst_bytes),
        np.log1p(src_packets),
        np.log1p(dst_packets),
        np.log1p(total_bytes),
        np.log1p(total_packets),
        np.log1p(avg_bytes),
        np.log1p(byte_ratio),
        np.log1p(pkt_ratio),
        proto_code,
        np.log1p(dst_port),
        np.zeros(n),
        np.zeros(n),
        np.zeros(n),
        np.zeros(n),
    ]
    matrix = np.vstack(cols).T.astype(float)  # (n, 16)
    if matrix.shape[1] != NODE_FEATURE_DIM:
        # Pad / trim defensively to the model's expected dimension.
        fixed = np.zeros((n, NODE_FEATURE_DIM), dtype=float)
        width = min(NODE_FEATURE_DIM, matrix.shape[1])
        fixed[:, :width] = matrix[:, :width]
        matrix = fixed
    return np.nan_to_num(matrix, nan=0.0, posinf=0.0, neginf=0.0)


def _effective_chunk_size(n_rows: int, cfg: GraphConfig) -> int:
    """
    Rows per graph, grown so the snapshot count stays within ``max_snapshots``.

    This is the core Module D scalability lever: for very large datasets the
    chunk size auto-increases (fewer, larger graphs) so memory stays bounded
    while every row is still covered.
    """
    base = max(10, cfg.rows_per_graph)
    if cfg.max_snapshots > 0 and n_rows > base * cfg.max_snapshots:
        # ceil(n_rows / max_snapshots)
        return max(base, -(-n_rows // cfg.max_snapshots))
    return base


def _iter_chunks(df: pd.DataFrame, size: int):
    """Yield contiguous row chunks of at most ``size`` rows (generator = low memory)."""
    if len(df) <= size:
        yield df
        return
    for i in range(0, len(df), size):
        yield df.iloc[i : i + size]


def _chunks(df: pd.DataFrame, size: int) -> list[pd.DataFrame]:
    """Split a dataframe into contiguous row chunks of at most ``size`` rows."""
    return list(_iter_chunks(df, size))


def _cap_snapshots(snapshots: list[dict[str, Any]], max_snapshots: int) -> list[dict[str, Any]]:
    """Evenly subsample snapshots to at most ``max_snapshots`` (preserves order)."""
    if max_snapshots <= 0 or len(snapshots) <= max_snapshots:
        return snapshots
    idx = np.linspace(0, len(snapshots) - 1, max_snapshots).round().astype(int)
    seen: set[int] = set()
    capped: list[dict[str, Any]] = []
    for i in idx:
        i = int(i)
        if i not in seen:
            seen.add(i)
            capped.append(snapshots[i])
    return capped


def _attack_votes(df: pd.DataFrame) -> list[str]:
    if "attack_type" in df.columns:
        return [str(v) for v in df["attack_type"].tolist()]
    if "raw_label" in df.columns:
        return [str(v) for v in df["raw_label"].tolist()]
    return ["Normal"] * len(df)


def _assemble_snapshot(
    node_features: list[list[float]],
    edge_pairs: list[tuple[int, int]],
    attack_votes: list[str],
    timestamp: datetime,
    *,
    directed: bool,
    node_kind: str,
) -> dict[str, Any]:
    """Assemble a strategy snapshot with the canonical schema."""
    n = len(node_features)
    if directed:
        pairs = list(edge_pairs)
    else:
        pairs = list(edge_pairs) + [(b, a) for (a, b) in edge_pairs]

    if not pairs and n:
        pairs = [(0, 0)]

    edge_index = [[a for a, _ in pairs], [b for _, b in pairs]]
    node_ids = [str(i) for i in range(n)]
    edges = [{"source": str(a), "target": str(b)} for a, b in pairs]
    majority = _majority_attack_type([v for v in attack_votes]) if attack_votes else "Normal"
    ts_iso = timestamp.isoformat() if hasattr(timestamp, "isoformat") else str(timestamp)

    return {
        "timestamp": ts_iso,
        "nodes": [{"id": str(i), "type": node_kind} for i in range(n)],
        "edges": edges,
        "node_features": node_features,
        "edge_index": edge_index,
        "node_count": n,
        "edge_count": len(pairs),
        "attack_type": majority,
        "label": 0 if majority == "Normal" else 1,
        "graph_metrics": _graph_metrics(node_ids, edges),
    }


# ---------------------------------------------------------------------------
# Strategy builders
# ---------------------------------------------------------------------------

def _build_temporal(df: pd.DataFrame, cfg: GraphConfig) -> list[dict[str, Any]]:
    """Endpoint graphs over sliding time windows (configurable size/overlap/stride)."""
    builder = TemporalGraphBuilder(window_seconds=cfg.window_size)
    work = builder._normalize_columns(df.copy())  # noqa: SLF001 (same package)
    if "timestamp" not in work.columns:
        work["timestamp"] = pd.date_range(start="2017-07-03", periods=len(work), freq="100ms")
    work["timestamp"] = pd.to_datetime(work["timestamp"], errors="coerce")
    work = work.dropna(subset=["timestamp"]).sort_values("timestamp").reset_index(drop=True)
    if work.empty:
        return []

    start = work["timestamp"].min()
    end = work["timestamp"].max()
    stride = cfg.effective_stride()

    snapshots: list[dict[str, Any]] = []
    current = start
    # Guard against pathological (huge span, tiny stride) loops.
    max_windows = 100000
    steps = 0
    while current < end and steps < max_windows:
        window_end = current + timedelta(seconds=cfg.window_size)
        window_df = work[(work["timestamp"] >= current) & (work["timestamp"] < window_end)]
        if len(window_df) > 0:
            snap = builder._build_snapshot(window_df, current)  # noqa: SLF001
            if not cfg.directed:
                _make_undirected(snap)
            snapshots.append(snap)
        current = current + timedelta(seconds=stride)
        steps += 1

    if not snapshots:
        snapshots.append(builder._build_snapshot(work, start.to_pydatetime()))  # noqa: SLF001
    return snapshots


def _build_endpoint(df: pd.DataFrame, cfg: GraphConfig) -> list[dict[str, Any]]:
    """Endpoint graphs built per fixed-size row chunk (no temporal windowing)."""
    builder = TemporalGraphBuilder(window_seconds=cfg.window_size)
    work = builder._normalize_columns(df.copy())  # noqa: SLF001
    snapshots: list[dict[str, Any]] = []
    base = datetime(2017, 1, 1)
    chunk_size = _effective_chunk_size(len(work), cfg)
    for i, chunk in enumerate(_iter_chunks(work, chunk_size)):
        if chunk.empty:
            continue
        snap = builder._build_snapshot(chunk, base + timedelta(seconds=i))  # noqa: SLF001
        if not cfg.directed:
            _make_undirected(snap)
        snapshots.append(snap)
    return snapshots


def _build_flow(df: pd.DataFrame, cfg: GraphConfig) -> list[dict[str, Any]]:
    """Flow graphs: each flow is a node; edges connect sequentially adjacent flows."""
    snapshots: list[dict[str, Any]] = []
    base = datetime(2017, 1, 1)
    d = cfg.flow_sequential_distance
    chunk_size = _effective_chunk_size(len(df), cfg)
    for idx, chunk in enumerate(_iter_chunks(df, chunk_size)):
        chunk = chunk.reset_index(drop=True)
        if chunk.empty:
            continue
        feats = _flow_feature_matrix(chunk).tolist()
        n = len(feats)
        edge_pairs: list[tuple[int, int]] = []
        for i in range(n):
            for j in range(i + 1, min(i + 1 + d, n)):
                edge_pairs.append((i, j))
        snapshots.append(
            _assemble_snapshot(
                feats,
                edge_pairs,
                _attack_votes(chunk),
                base + timedelta(seconds=idx),
                directed=cfg.directed,
                node_kind="flow",
            )
        )
    return snapshots


def _build_similarity(df: pd.DataFrame, cfg: GraphConfig) -> list[dict[str, Any]]:
    """Feature-similarity graphs: flows linked by cosine threshold or kNN."""
    snapshots: list[dict[str, Any]] = []
    base = datetime(2017, 1, 1)
    metric = (cfg.similarity_metric or "cosine").strip().lower()

    # Similarity is O(n^2) per chunk, so the chunk size is capped by
    # ``max_flow_nodes`` regardless of the global scalability lever.
    sim_chunk = min(cfg.rows_per_graph, cfg.max_flow_nodes)
    for idx, chunk in enumerate(_iter_chunks(df, sim_chunk)):
        chunk = chunk.reset_index(drop=True)
        if chunk.empty:
            continue
        matrix = _flow_feature_matrix(chunk)
        n = matrix.shape[0]
        feats = matrix.tolist()

        # Cosine similarity on L2-normalized rows.
        norms = np.linalg.norm(matrix, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        unit = matrix / norms
        sim = unit @ unit.T
        np.fill_diagonal(sim, -np.inf)

        edge_pairs: list[tuple[int, int]] = []
        if metric == "knn":
            k = min(cfg.similarity_neighbors, max(n - 1, 1))
            for i in range(n):
                if n <= 1:
                    break
                nn_idx = np.argpartition(sim[i], -k)[-k:]
                for j in nn_idx:
                    j = int(j)
                    if j != i and sim[i, j] > -np.inf:
                        a, b = (i, j) if i < j else (j, i)
                        edge_pairs.append((a, b))
        else:  # cosine threshold
            thr = cfg.similarity_threshold
            iu = np.triu_indices(n, k=1)
            mask = sim[iu] >= thr
            for a, b in zip(iu[0][mask].tolist(), iu[1][mask].tolist()):
                edge_pairs.append((int(a), int(b)))

        # De-duplicate undirected pairs.
        edge_pairs = list({(a, b) for a, b in edge_pairs})

        snapshots.append(
            _assemble_snapshot(
                feats,
                edge_pairs,
                _attack_votes(chunk),
                base + timedelta(seconds=idx),
                directed=False,  # similarity is inherently symmetric
                node_kind="flow",
            )
        )
    return snapshots


def _make_undirected(snapshot: dict[str, Any]) -> None:
    """Add reverse edges to an endpoint snapshot's edge_index in place."""
    ei = snapshot.get("edge_index") or [[], []]
    src, dst = ei[0], ei[1]
    snapshot["edge_index"] = [src + dst, dst + src]
    snapshot["edge_count"] = len(snapshot["edge_index"][0])


# ---------------------------------------------------------------------------
# Public dispatcher
# ---------------------------------------------------------------------------

def build_snapshots(df: pd.DataFrame, config: GraphConfig) -> list[dict[str, Any]]:
    """Build graph snapshots from a preprocessed dataframe using the given strategy."""
    from app.data.preprocess import apply_feature_set
    from app.services.feature_selection import mask_snapshot

    strategy = normalize_strategy(config.strategy)
    work = apply_feature_set(df, config.feature_set)

    if strategy == "endpoint":
        snaps = _build_endpoint(work, config)
    elif strategy == "flow":
        snaps = _build_flow(work, config)
    elif strategy == "similarity":
        snaps = _build_similarity(work, config)
    else:
        snaps = _build_temporal(work, config)

    if config.feature_set:
        snaps = [mask_snapshot(s, config.feature_set, strategy=strategy) for s in snaps]

    # Scalability safety net (Module D): bound snapshot count for huge inputs.
    return _cap_snapshots(snaps, config.max_snapshots)


def build_one_snapshot(df: pd.DataFrame, config: GraphConfig) -> dict[str, Any]:
    """Build a single representative snapshot (for /graph/build and inference)."""
    snaps = build_snapshots(df, config)
    non_empty = [s for s in snaps if s.get("node_count", 0) > 0]
    if non_empty:
        # Return the largest snapshot so callers see a meaningful graph.
        return max(non_empty, key=lambda s: s.get("node_count", 0))
    # Fall back to an endpoint single snapshot.
    builder = TemporalGraphBuilder(window_seconds=config.window_size)
    return builder.build_single_snapshot(df)


def graph_structure_stats(snapshots: list[dict[str, Any]]) -> dict[str, float]:
    """Aggregate node/edge/density/degree stats across snapshots (for reporting)."""
    labeled = [s for s in snapshots if s.get("node_count", 0) > 0]
    if not labeled:
        return {
            "num_snapshots": 0,
            "avg_nodes": 0.0,
            "avg_edges": 0.0,
            "avg_density": 0.0,
            "avg_degree": 0.0,
        }
    nodes = [s.get("node_count", 0) for s in labeled]
    edges = [s.get("edge_count", 0) for s in labeled]
    densities = [float(s.get("graph_metrics", {}).get("density", 0.0)) for s in labeled]
    degrees = [float(s.get("graph_metrics", {}).get("avg_degree", 0.0)) for s in labeled]
    return {
        "num_snapshots": len(labeled),
        "avg_nodes": round(float(np.mean(nodes)), 2),
        "avg_edges": round(float(np.mean(edges)), 2),
        "avg_density": round(float(np.mean(densities)), 4),
        "avg_degree": round(float(np.mean(degrees)), 2),
    }
