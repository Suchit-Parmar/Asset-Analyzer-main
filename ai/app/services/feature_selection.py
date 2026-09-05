"""Model Studio feature selection (Phase 3).

The UI exposes six toggles (timestamp, packet_size, protocol, ports,
flow_duration, tcp_flags). Each toggle affects:

* **Preprocessing** — canonical dataframe columns are zeroed / neutralised
  before graph construction when a group is disabled.
* **Graph features** — the corresponding dimensions in the 16-dim node
  vectors are masked to zero after vectors are built.
* **Inference** — the same mask from the active checkpoint is applied so
  live predictions match the training feature space.

The model always receives a fixed 16-dim input; disabled groups contribute
zeros rather than changing the architecture, preserving backward
compatibility with existing checkpoints.
"""

from __future__ import annotations

from typing import Any

import numpy as np

from app.graph.builder import NODE_FEATURE_DIM

# Must stay in sync with config_store.DEFAULT_FEATURE_SET and the frontend.
DEFAULT_FEATURE_SET: dict[str, bool] = {
    "timestamp": True,
    "packet_size": True,
    "protocol": True,
    "ports": True,
    "flow_duration": True,
    "tcp_flags": False,
}

FEATURE_LABELS: dict[str, str] = {
    "timestamp": "Timestamp",
    "packet_size": "Packet Size",
    "protocol": "Protocol",
    "ports": "Port No.",
    "flow_duration": "Flow Duration",
    "tcp_flags": "TCP Flags",
}

# Dimension indices per feature group for endpoint-style node vectors
# (endpoint + temporal strategies via TemporalGraphBuilder).
ENDPOINT_DIM_GROUPS: dict[str, list[int]] = {
    "packet_size": [0, 1, 6],
    "ports": [4],
    "tcp_flags": [8, 9, 10, 11, 12, 13, 14, 15],
}

# Dimension indices for flow / similarity strategies (_flow_feature_matrix).
FLOW_DIM_GROUPS: dict[str, list[int]] = {
    "flow_duration": [0],
    "packet_size": [1, 2, 3, 4, 5, 6, 7, 8, 9],
    "protocol": [10],
    "ports": [11],
    "tcp_flags": [12, 13, 14, 15],
}

# Manual single-node inference vector (_prepare_tensors fallback).
INFERENCE_DIM_GROUPS: dict[str, list[int]] = {
    "flow_duration": [0],
    "packet_size": [1, 2, 3, 4],
    "protocol": [11],
    "ports": [11],
    "tcp_flags": [12, 13, 14, 15],
}


def normalize_feature_set(raw: dict[str, Any] | None) -> dict[str, bool]:
    """Merge incoming toggles with defaults; coerce truthy/falsy values."""
    merged = dict(DEFAULT_FEATURE_SET)
    if not raw:
        return merged
    # Older checkpoints stored metadata like {"node_feature_dim": 16, ...}
    for key in DEFAULT_FEATURE_SET:
        if key in raw:
            merged[key] = bool(raw[key])
    return merged


def vector_kind_for_strategy(strategy: str | None) -> str:
    """Return ``endpoint`` or ``flow`` for masking node feature vectors."""
    s = (strategy or "temporal").strip().lower()
    if s in ("flow", "similarity"):
        return "flow"
    return "endpoint"


def dim_groups_for_kind(kind: str) -> dict[str, list[int]]:
    if kind == "flow":
        return FLOW_DIM_GROUPS
    if kind == "inference":
        return INFERENCE_DIM_GROUPS
    return ENDPOINT_DIM_GROUPS


def mask_vector(vec: list[float] | np.ndarray, feature_set: dict[str, bool] | None,
                *, kind: str = "endpoint") -> list[float]:
    """Zero-out dimensions belonging to disabled feature groups."""
    fs = normalize_feature_set(feature_set)
    groups = dim_groups_for_kind(kind)
    out = [float(v) for v in vec]
    while len(out) < NODE_FEATURE_DIM:
        out.append(0.0)
    out = out[:NODE_FEATURE_DIM]
    for group, indices in groups.items():
        if fs.get(group, True):
            continue
        for idx in indices:
            if 0 <= idx < len(out):
                out[idx] = 0.0
    return out


def mask_node_features(
    features: list[list[float]],
    feature_set: dict[str, bool] | None,
    *,
    kind: str = "endpoint",
) -> list[list[float]]:
    return [mask_vector(row, feature_set, kind=kind) for row in features]


def mask_snapshot(
    snapshot: dict[str, Any],
    feature_set: dict[str, bool] | None,
    *,
    strategy: str | None = None,
) -> dict[str, Any]:
    """Apply feature masking to a graph snapshot dict (in-place safe copy)."""
    if not snapshot or "node_features" not in snapshot:
        return snapshot
    kind = vector_kind_for_strategy(strategy or snapshot.get("graph_strategy"))
    out = dict(snapshot)
    out["node_features"] = mask_node_features(
        snapshot["node_features"], feature_set, kind=kind
    )
    return out


def metadata_payload(
    feature_set: dict[str, bool] | None,
    *,
    strategy: str | None = None,
    node_feature_dim: int = NODE_FEATURE_DIM,
) -> dict[str, Any]:
    """Compact feature-set record stored in checkpoints / metrics."""
    fs = normalize_feature_set(feature_set)
    enabled = [k for k, v in fs.items() if v]
    disabled = [k for k, v in fs.items() if not v]
    return {
        **fs,
        "enabled": enabled,
        "disabled": disabled,
        "node_feature_dim": node_feature_dim,
        "node_kind": vector_kind_for_strategy(strategy),
    }
