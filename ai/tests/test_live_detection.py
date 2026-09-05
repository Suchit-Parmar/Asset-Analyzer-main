"""Phase 11 — live detection: interfaces, capture lifecycle, flows, graph, leakage, inference."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch

import numpy as np
import pytest

from app.graph.builder import NODE_FEATURE_DIM, TemporalGraphBuilder
from app.live.capture import PacketEvent, list_interfaces, validate_interface_name
from app.live.feature_extractor import flows_to_dataframe
from app.live.flow_processor import FlowAggregator, FlowRecord
from app.live.live_manager import LiveManager
from app.services.inference import inference_service


def _pkt(
    src: str = "192.168.1.10",
    dst: str = "8.8.8.8",
    sport: int = 54321,
    dport: int = 443,
    proto: str = "tcp",
    length: int = 100,
    flags: int | None = 0x18,
) -> PacketEvent:
    return PacketEvent(
        timestamp=datetime.now(timezone.utc),
        src_ip=src,
        dst_ip=dst,
        src_port=sport,
        dst_port=dport,
        protocol=proto,
        length=length,
        tcp_flags=flags,
    )


# ---------------------------------------------------------------------------
# 1. Interface discovery
# ---------------------------------------------------------------------------


def test_list_interfaces_returns_real_nics_or_empty():
    ifaces = list_interfaces()
    assert isinstance(ifaces, list)
    # Must never invent the old fake "any" fallback.
    assert all(i.get("name") != "any" for i in ifaces)
    for i in ifaces:
        assert "name" in i and i["name"]
        assert "display_name" in i
        assert "is_up" in i
        assert "ipv4" in i


# ---------------------------------------------------------------------------
# 2. Invalid interface handling
# ---------------------------------------------------------------------------


def test_validate_rejects_shell_metacharacters():
    with pytest.raises(ValueError, match="Invalid"):
        validate_interface_name("eth0; rm -rf /")
    with pytest.raises(ValueError, match="Invalid"):
        validate_interface_name("eth0|whoami")
    with pytest.raises(ValueError, match="Invalid"):
        validate_interface_name("../etc/passwd")


def test_validate_rejects_unknown_interface():
    with pytest.raises(ValueError, match="Unknown"):
        validate_interface_name("__definitely_not_a_real_iface_zz__")


def test_start_rejects_invalid_window():
    mgr = LiveManager()
    with pytest.raises(ValueError, match="window_seconds"):
        mgr.start("whatever", window_seconds=7)


def test_start_rejects_unknown_iface_before_capture():
    mgr = LiveManager()
    with pytest.raises(ValueError, match="Unknown"):
        mgr.start("__no_such_iface__", window_seconds=5)
    assert mgr.status()["running"] is False


# ---------------------------------------------------------------------------
# 3. Capture lifecycle (mocked sniffer — no Npcap required)
# ---------------------------------------------------------------------------


def test_capture_lifecycle_start_stop_and_single_worker():
    mgr = LiveManager()
    fake_iface = {"name": "test0", "display_name": "Test", "ipv4": "10.0.0.2", "is_up": True}

    class _FakeSniffer:
        def start(self):
            self.started = True

        def stop(self):
            self.stopped = True

    def _start_ok(self, iface: str) -> None:
        if self._running:
            raise RuntimeError("Capture already running — stop it first")
        self._iface = iface
        self._packet_count = 0
        self._error = None
        sn = _FakeSniffer()
        sn.start()
        self._sniffer = sn
        self._running = True

    with (
        patch("app.live.live_manager.list_interfaces", return_value=[fake_iface]),
        patch("app.live.capture.list_interfaces", return_value=[fake_iface]),
        patch("app.live.live_manager.validate_interface_name", return_value="test0"),
        patch("app.live.capture.LiveCapture.start", _start_ok),
    ):
        st = mgr.start("test0", window_seconds=5)
        assert st["running"] is True
        assert st["interface"] == "test0"
        assert st["window_seconds"] == 5

        with pytest.raises(RuntimeError, match="already running"):
            mgr.start("test0", window_seconds=5)

        stopped = mgr.stop()
        assert stopped["running"] is False
        assert stopped["status"] == "stopped"

        st2 = mgr.start("test0", window_seconds=10)
        assert st2["running"] is True
        assert st2["window_seconds"] == 10
        mgr.stop()


def test_down_interface_rejected():
    mgr = LiveManager()
    down = {"name": "down0", "display_name": "Down", "ipv4": None, "is_up": False}
    with (
        patch("app.live.live_manager.list_interfaces", return_value=[down]),
        patch("app.live.capture.list_interfaces", return_value=[down]),
        patch("app.live.live_manager.validate_interface_name", return_value="down0"),
    ):
        with pytest.raises(ValueError, match="down"):
            mgr.start("down0", window_seconds=5)


# ---------------------------------------------------------------------------
# 4. Packet → flow conversion
# ---------------------------------------------------------------------------


def test_packet_to_flow_aggregation_bidirectional_and_tcp_flags():
    agg = FlowAggregator()
    a = _pkt(src="10.0.0.1", dst="10.0.0.2", sport=1000, dport=80, length=60, flags=0x02)
    b = _pkt(src="10.0.0.2", dst="10.0.0.1", sport=80, dport=1000, length=40, flags=0x12)
    agg.ingest([a, b])
    flows = agg.flush()
    assert len(flows) == 1
    f = flows[0]
    assert f.packet_count == 2
    assert f.byte_count == 100
    assert f.tcp_flags == (0x02 | 0x12)
    assert agg.flush() == []


# ---------------------------------------------------------------------------
# 5. Flow → graph conversion
# ---------------------------------------------------------------------------


def test_flow_to_graph_conversion():
    now = datetime.now(timezone.utc)
    flows = [
        FlowRecord(
            src_ip="192.168.1.10",
            dst_ip="8.8.8.8",
            src_port=40000,
            dst_port=53,
            protocol="udp",
            src_packets=2,
            dst_packets=2,
            src_bytes=120,
            dst_bytes=200,
            first_seen=now,
            last_seen=now,
            dns_name="dns.google",
            tcp_flags=0,
        )
    ]
    df = flows_to_dataframe(flows)
    snap = TemporalGraphBuilder(window_seconds=5).build_single_snapshot(df)
    assert snap["node_count"] >= 2
    assert snap["edge_count"] >= 1
    feats = np.asarray(snap["node_features"])
    assert feats.shape[1] == NODE_FEATURE_DIM


# ---------------------------------------------------------------------------
# 6. Leakage-free live feature construction
# ---------------------------------------------------------------------------


def test_live_features_have_no_attack_label_columns_or_target_leakage():
    flows = [
        FlowRecord(
            src_ip="192.168.0.5",
            dst_ip="1.1.1.1",
            src_port=5555,
            dst_port=443,
            protocol="tcp",
            src_packets=4,
            dst_packets=3,
            src_bytes=900,
            dst_bytes=700,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
    ]
    df = flows_to_dataframe(flows)
    assert "attack_type" not in df.columns
    assert "raw_label" not in df.columns
    assert "Label" not in df.columns

    snap = TemporalGraphBuilder(window_seconds=10).build_single_snapshot(df)
    # Live manager forces unknown; builder alone has no labels → Normal majority.
    # Features must still be observable-only (reserved dims zero).
    feats = np.asarray(snap["node_features"], dtype=float)
    assert np.all(feats[:, 8:] == 0.0)


def test_live_manager_window_sets_unknown_label_not_fake_attack():
    mgr = LiveManager()
    events = [
        _pkt(),
        _pkt(sport=54322, length=80),
        _pkt(src="8.8.8.8", dst="192.168.1.10", sport=443, dport=54321, length=60),
    ]
    # Inject packets without starting real capture.
    with mgr._lock:
        mgr._window_seconds = 5
        mgr._session_id = "test-session"
        mgr._capture._buffer.extend(events)
        mgr._capture._packet_count = len(events)
        mgr._process_window(final=False)

    assert mgr._latest is not None
    assert mgr._latest.get("source") == "live"
    assert mgr._latest.get("attack_type") == "unknown"
    assert mgr._latest.get("label") is None
    assert int(mgr._latest.get("node_count") or 0) >= 1
    # Empty fabrication check: threats only from model, not hardcoded.
    if mgr._prediction is None or mgr._prediction.get("is_unknown"):
        assert mgr._threat_count(mgr._prediction) == 0


# ---------------------------------------------------------------------------
# 7. Inference integration
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not inference_service.is_loaded, reason="TGNN checkpoint not available")
def test_live_inference_integration_returns_model_fields():
    now = datetime.now(timezone.utc)
    flows = [
        FlowRecord(
            src_ip="192.168.1.20",
            dst_ip="93.184.216.34",
            src_port=50000,
            dst_port=443,
            protocol="tcp",
            src_packets=10,
            dst_packets=8,
            src_bytes=4000,
            dst_bytes=8000,
            first_seen=now,
            last_seen=now,
        )
    ]
    df = flows_to_dataframe(flows)
    snap = TemporalGraphBuilder(window_seconds=5).build_single_snapshot(df)
    snap["attack_type"] = "unknown"
    snap["label"] = None
    result = inference_service.predict({}, snap)

    assert result.get("attack_type") is not None
    assert isinstance(result.get("confidence"), float)
    assert "detection" in result
    assert result["detection"]["status"] in ("BENIGN", "ATTACK")
    assert "next_window_prediction" in result
    # No hardcoded threat theatre — Normal is allowed and honest.
    if str(result["attack_type"]).lower() == "normal":
        assert result["detection"]["status"] == "BENIGN"


# ---------------------------------------------------------------------------
# 8. WebSocket / status result delivery contract
# ---------------------------------------------------------------------------


def test_status_payload_matches_frontend_live_contract():
    mgr = LiveManager()
    st = mgr.status()
    required = {
        "mode",
        "status",
        "running",
        "interface",
        "window_seconds",
        "stats",
        "prediction",
        "snapshot",
        "message",
        "error",
        "model_loaded",
    }
    assert required.issubset(st.keys())
    for key in ("packets", "flows", "active_nodes", "connections", "threats", "suspicious_nodes"):
        assert key in st["stats"]


def test_live_sync_broadcast_shape_helpers():
    """Mirror Express live-sync: topology + risk payloads derived from status."""
    mgr = LiveManager()
    with mgr._lock:
        mgr._iface = "eth0"
        mgr._window_seconds = 5
        mgr._status = "running"
        mgr._capture._running = True
        mgr._latest = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "nodes": [{"id": "a", "ip": "10.0.0.1", "risk_score": 0.1, "status": "online"}],
            "edges": [],
            "node_count": 1,
            "edge_count": 0,
        }
        mgr._prediction = {
            "attack_type": "Normal",
            "confidence": 0.9,
            "risk_score": 0.1,
            "is_unknown": False,
            "detection": {"status": "BENIGN"},
            "next_window_prediction": {"enabled": True, "predicted_stage": "normal"},
        }

    st = mgr.status()
    # Shape Express uses for WS fan-out
    topology = {
        "source": "live",
        "timestamp": st["snapshot"]["timestamp"],
        "stats": st["stats"],
        "prediction": st["prediction"],
    }
    assert topology["source"] == "live"
    assert topology["prediction"]["attack_type"] == "Normal"
    assert topology["stats"]["threats"] == 0  # Normal ≠ threat
    risk_update = {
        "source": "live",
        "risk_score": st["prediction"]["risk_score"],
        "confidence": st["prediction"]["confidence"],
        "attack_type": st["prediction"]["attack_type"],
    }
    assert risk_update["attack_type"] == "Normal"


def test_empty_window_does_not_fabricate_prediction():
    mgr = LiveManager()
    with mgr._lock:
        mgr._window_seconds = 5
        mgr._process_window(final=False)
    assert mgr._prediction is None
    assert mgr._threat_count(mgr._prediction) == 0
