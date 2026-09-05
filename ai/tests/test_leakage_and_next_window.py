"""Leakage and next-window contract tests (no fake metrics)."""

from __future__ import annotations

import pandas as pd

from app.graph.builder import TemporalGraphBuilder, ENDPOINT_FEATURE_NAMES
from app.models.tgnn import TGNNModel
import torch


def test_failed_logins_not_derived_from_attack_label():
    """Identical traffic with different labels must produce identical node features."""
    rows = []
    for label in ("Normal", "Brute Force", "FTP-Patator", "SSH-Patator", "DDoS"):
        rows.append(
            {
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "src_port": 40000,
                "dst_port": 22,
                "protocol": "tcp",
                "src_packets": 2,
                "dst_packets": 1,
                "src_bytes": 80,
                "dst_bytes": 40,
                "duration": 0.2,
                "attack_type": label,
            }
        )
    df = pd.DataFrame(rows)
    builder = TemporalGraphBuilder(window_seconds=30)
    snap = builder.build_single_snapshot(df)
    # All rows share same endpoints; feature vectors must not encode the label.
    feats = snap["node_features"]
    assert len(feats) >= 1
    # Auth-port short-flow bursts may increment from traffic, but must be equal
    # regardless of which attack_type string was attached to each identical flow.
    # Rebuild one-row-at-a-time and compare dim-3 across labels.
    dim3 = []
    for label in ("Normal", "Brute Force", "DDoS"):
        one = df.iloc[[0]].copy()
        one["attack_type"] = label
        s = builder.build_single_snapshot(one)
        # dst node feature index 3
        dst_feat = None
        for node, vec in zip(s["nodes"], s["node_features"]):
            if node["ip"] == "10.0.0.2":
                dst_feat = vec[3]
                break
        assert dst_feat is not None
        dim3.append(dst_feat)
    assert dim3[0] == dim3[1] == dim3[2], "Label must not change auth-port burst feature"


def test_endpoint_feature_name_dim3_is_auth_port_bursts():
    assert ENDPOINT_FEATURE_NAMES[3] == "log_auth_port_bursts"


def test_tgnn_forward_uses_edge_index_and_optional_temporal():
    model = TGNNModel(node_features=16, hidden_dim=32, architecture="gcn")
    model.eval()
    x = torch.randn(4, 16)
    ei = torch.tensor([[0, 1, 2], [1, 2, 3]], dtype=torch.long)
    temporal = torch.randn(1, 2, 32)
    out = model(x, ei, temporal_seq=temporal)
    assert "attack_logits" in out
    assert "next_stage_logits" in out
    assert out["attack_logits"].shape[-1] > 1
