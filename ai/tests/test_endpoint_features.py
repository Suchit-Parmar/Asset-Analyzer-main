"""Tests for endpoint feature naming, live graph vectors, and honest live labels."""

from __future__ import annotations

from datetime import datetime, timezone

import numpy as np
import pytest
import torch

from app.graph.builder import (
    ENDPOINT_FEATURE_NAMES,
    ENDPOINT_RESERVED_INDICES,
    NODE_FEATURE_DIM,
    TemporalGraphBuilder,
    endpoint_feature_name,
    is_reserved_endpoint_dim,
)
from app.graph.strategies import GraphConfig, build_one_snapshot
from app.live.feature_extractor import flows_to_dataframe
from app.live.flow_processor import FlowRecord
from app.live.live_manager import LiveManager
from app.services.inference import inference_service


WRONG_CICIDS_NAMES = {
    "duration",
    "src_bytes",
    "dst_bytes",
    "src_packets",
    "dst_packets",
    "serror_rate",
    "same_srv_rate",
    "root_shell",
}


def test_endpoint_feature_names_length_and_order():
    assert len(ENDPOINT_FEATURE_NAMES) == 16
    assert ENDPOINT_FEATURE_NAMES[0] == "log_packets"
    assert ENDPOINT_FEATURE_NAMES[7] == "conn_ratio"
    assert ENDPOINT_FEATURE_NAMES[8] == "reserved_9"
    assert ENDPOINT_FEATURE_NAMES[15] == "reserved_16"
    for i, name in enumerate(ENDPOINT_FEATURE_NAMES):
        assert endpoint_feature_name(i) == name


def test_reserved_dims_are_indices_8_through_15():
    assert ENDPOINT_RESERVED_INDICES == tuple(range(8, 16))
    for i in range(8):
        assert not is_reserved_endpoint_dim(i)
    for i in range(8, 16):
        assert is_reserved_endpoint_dim(i)


def _sample_live_flows() -> list[FlowRecord]:
    now = datetime.now(timezone.utc)
    return [
        FlowRecord(
            src_ip="192.168.1.10",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol="tcp",
            src_packets=5,
            dst_packets=3,
            src_bytes=1200,
            dst_bytes=800,
            first_seen=now,
            last_seen=now,
            dns_name="dns.google",
        )
    ]


def test_live_snapshot_has_sixteen_dim_features_with_zero_padding():
    df = flows_to_dataframe(_sample_live_flows())
    assert "attack_type" not in df.columns

    builder = TemporalGraphBuilder(window_seconds=5)
    snapshot = builder.build_single_snapshot(df)
    feats = np.asarray(snapshot["node_features"], dtype=float)

    assert feats.ndim == 2
    assert feats.shape[1] == NODE_FEATURE_DIM == 16
    assert np.all(feats[:, 8:] == 0.0)


def test_feature_importance_uses_endpoint_names_not_cicids():
    if not inference_service.is_loaded:
        pytest.skip("TGNN checkpoint not available")

    df = flows_to_dataframe(_sample_live_flows())
    snapshot = TemporalGraphBuilder(window_seconds=5).build_single_snapshot(df)
    x, _ = inference_service._prepare_tensors({}, snapshot)
    top = inference_service._feature_importance(x)

    assert top, "expected non-empty feature importance"
    reported = {item["feature"] for item in top}
    assert reported.isdisjoint(WRONG_CICIDS_NAMES)
    assert "log_packets" in reported or "log_bytes" in reported
    for item in top:
        idx = item.get("index", ENDPOINT_FEATURE_NAMES.index(item["feature"]))
        assert not is_reserved_endpoint_dim(idx)
        assert not str(item["feature"]).startswith("reserved_")


def test_failed_live_inference_is_not_normal():
    mgr = LiveManager()
    unavailable = {
        "attack_type": None,
        "confidence": None,
        "risk_score": None,
        "threat_level": "info",
        "is_unknown": True,
        "source": "live",
        "message": "Prediction unavailable",
    }
    assert mgr._threat_count(unavailable) == 0
    assert unavailable["attack_type"] is None
    assert unavailable["is_unknown"] is True


def test_dataset_replay_still_builds_valid_snapshot():
    from app.data.loaders import load_dataset

    df = load_dataset("cse_cic_ids2018", max_rows=200)
    cfg = GraphConfig.from_dict(
        "temporal",
        {"window_size": 30, "window_overlap": 0, "window_stride": 30},
    )
    snapshot = build_one_snapshot(df, cfg)
    feats = np.asarray(snapshot["node_features"], dtype=float)

    assert snapshot.get("node_count", 0) > 0
    assert feats.shape[1] == 16
    assert snapshot.get("attack_type") not in (None, "unknown")


@pytest.mark.skipif(not inference_service.is_loaded, reason="TGNN checkpoint not available")
def test_live_inference_returns_model_attack_type():
    df = flows_to_dataframe(_sample_live_flows())
    snapshot = TemporalGraphBuilder(window_seconds=5).build_single_snapshot(df)
    snapshot["attack_type"] = "unknown"
    result = inference_service.predict({}, snapshot)
    assert result["attack_type"] is not None
    assert isinstance(result["confidence"], float)
    top = result["explanation"]["top_features"]
    names = {f["feature"] for f in top}
    assert names.isdisjoint(WRONG_CICIDS_NAMES)
