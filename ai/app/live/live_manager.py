"""Orchestrate live capture → flow windows → GNN inference."""

from __future__ import annotations

import logging
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any

from app.graph.builder import TemporalGraphBuilder
from app.live.capture import LiveCapture, list_interfaces
from app.live.feature_extractor import flows_to_dataframe
from app.live.flow_processor import FlowAggregator

logger = logging.getLogger(__name__)

_MAX_WINDOWS = 48
_ALLOWED_WINDOWS = {5, 10, 30}


class LiveManager:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._capture = LiveCapture()
        self._aggregator = FlowAggregator()
        self._timer: threading.Timer | None = None
        self._window_seconds = 5
        self._iface: str | None = None
        self._started_at: str | None = None
        self._last_update: str | None = None
        self._windows: deque[dict[str, Any]] = deque(maxlen=_MAX_WINDOWS)
        self._latest: dict[str, Any] | None = None
        self._prediction: dict[str, Any] | None = None
        self._status = "stopped"  # stopped | running | error | waiting
        self._error: str | None = None
        self._total_packets = 0
        self._total_flows = 0
        self._window_seq = 0
        self._session_id: str | None = None

    def list_interfaces(self) -> list[dict[str, Any]]:
        return list_interfaces()

    def status(self) -> dict[str, Any]:
        with self._lock:
            snap = self._latest
            pred = self._prediction
            waiting = (
                self._status == "running"
                and (snap is None or int(snap.get("node_count") or 0) == 0)
            )
            return {
                "mode": "live",
                "status": "waiting" if waiting else self._status,
                "running": self._capture.running,
                "interface": self._iface,
                "window_seconds": self._window_seconds,
                "session_id": self._session_id,
                "started_at": self._started_at,
                "last_update": self._last_update,
                "error": self._error or self._capture.last_error,
                "model_loaded": self._model_loaded(),
                "stats": {
                    "packets": self._total_packets + self._capture.packet_count,
                    "flows": self._total_flows,
                    "active_nodes": int(snap.get("node_count") or 0) if snap else 0,
                    "connections": int(snap.get("edge_count") or 0) if snap else 0,
                    "windows": len(self._windows),
                    "threats": self._threat_count(pred),
                    "suspicious_nodes": self._suspicious_count(snap, pred),
                },
                "prediction": pred,
                "snapshot": snap,
                "message": self._status_message(waiting),
                "label": "LIVE = Authorized Local Network Monitoring",
            }

    def start(self, interface: str, window_seconds: int = 5) -> dict[str, Any]:
        window_seconds = int(window_seconds)
        if window_seconds not in _ALLOWED_WINDOWS:
            raise ValueError(f"window_seconds must be one of {sorted(_ALLOWED_WINDOWS)}")
        if not interface or not str(interface).strip():
            raise ValueError("interface is required")

        with self._lock:
            if self._capture.running:
                raise RuntimeError("Live detection already running")

            self._error = None
            self._window_seconds = window_seconds
            self._iface = str(interface).strip()
            self._aggregator = FlowAggregator()
            self._windows.clear()
            self._latest = None
            self._prediction = None
            self._total_packets = 0
            self._total_flows = 0
            self._window_seq = 0
            self._session_id = str(uuid.uuid4())
            self._started_at = datetime.now(timezone.utc).isoformat()
            self._last_update = None

            try:
                self._capture.start(self._iface)
            except PermissionError as exc:
                self._status = "error"
                self._error = str(exc)
                raise
            except Exception as exc:
                self._status = "error"
                self._error = str(exc)
                raise

            self._status = "running"
            self._arm_timer()

        return self.status()

    def stop(self) -> dict[str, Any]:
        with self._lock:
            self._cancel_timer()
            try:
                self._capture.stop()
            except Exception as exc:
                logger.warning("capture stop: %s", exc)
            # Final flush so UI can show last window if any.
            try:
                self._process_window(final=True)
            except Exception as exc:
                logger.debug("final window: %s", exc)
            self._status = "stopped"
            self._error = None
        return self.status()

    def history(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._windows)

    # ------------------------------------------------------------------
    def _model_loaded(self) -> bool:
        try:
            from app.services.inference import inference_service
            return bool(inference_service.is_loaded)
        except Exception:
            return False

    def _status_message(self, waiting: bool) -> str:
        if self._status == "error":
            return self._error or "Live detection error"
        if self._status == "stopped":
            return "LIVE DETECTION STOPPED"
        if waiting:
            return "Waiting for network traffic..."
        if not self._model_loaded():
            return "LIVE DETECTION ACTIVE — Prediction unavailable (model not loaded)"
        return "LIVE DETECTION ACTIVE"

    @staticmethod
    def _threat_count(pred: dict[str, Any] | None) -> int:
        if not pred or pred.get("is_unknown"):
            return 0
        attack = pred.get("attack_type")
        if not attack or str(attack).lower() in ("unknown", "normal"):
            return 0
        return 1

    @staticmethod
    def _suspicious_count(snap: dict[str, Any] | None, pred: dict[str, Any] | None) -> int:
        if not snap:
            return 0
        risk = float((pred or {}).get("risk_score") or 0)
        nodes = snap.get("nodes") or []
        if risk >= 0.6 and nodes:
            # Surface high-risk live window as suspicious node count (conservative).
            return min(3, max(1, len(nodes) // 10 or 1))
        return sum(1 for n in nodes if int(n.get("failed_logins") or 0) > 0)

    def _arm_timer(self) -> None:
        self._cancel_timer()
        self._timer = threading.Timer(self._window_seconds, self._on_tick)
        self._timer.daemon = True
        self._timer.start()

    def _cancel_timer(self) -> None:
        if self._timer is not None:
            try:
                self._timer.cancel()
            except Exception:
                pass
            self._timer = None

    def _on_tick(self) -> None:
        try:
            with self._lock:
                if not self._capture.running:
                    return
                self._process_window(final=False)
                if self._capture.running:
                    self._arm_timer()
        except Exception as exc:
            logger.exception("live window tick failed: %s", exc)
            with self._lock:
                self._error = f"Window processing failed: {exc}"
                if self._capture.running:
                    self._arm_timer()

    def _process_window(self, final: bool = False) -> None:
        events = self._capture.drain()
        if events:
            self._aggregator.ingest(events)
            self._total_packets += len(events)

        flows = self._aggregator.flush()
        if not flows and not final:
            # Empty window — keep waiting state, do not fabricate predictions.
            self._last_update = datetime.now(timezone.utc).isoformat()
            if self._latest is None:
                self._latest = {
                    "timestamp": self._last_update,
                    "window_seconds": self._window_seconds,
                    "nodes": [],
                    "edges": [],
                    "node_features": [],
                    "edge_index": [[0], [0]],
                    "node_count": 0,
                    "edge_count": 0,
                    "attack_type": "unknown",
                    "label": None,
                    "source": "live",
                }
            self._prediction = None
            return

        if not flows:
            return

        self._total_flows += len(flows)
        dns = {}
        for f in flows:
            name = f.dns_name or self._capture.peek_dns(f.dst_ip) or self._capture.peek_dns(f.src_ip)
            if name:
                dns[f.dst_ip] = name
                dns[f.src_ip] = name

        df = flows_to_dataframe(flows, dns_lookup=dns)
        builder = TemporalGraphBuilder(window_seconds=self._window_seconds)
        snapshot = builder.build_single_snapshot(df)
        snapshot["source"] = "live"
        snapshot["window_seconds"] = self._window_seconds
        snapshot["session_id"] = self._session_id
        # Live traffic has no ground-truth label; only model predictions count.
        snapshot["attack_type"] = "unknown"
        snapshot["label"] = None

        # Attach passively observed hostnames onto nodes when available.
        ip_host = {**dns}
        for row in df.itertuples(index=False):
            host = getattr(row, "hostname", None)
            if host:
                ip_host[str(getattr(row, "dst_ip"))] = str(host)
        for node in snapshot.get("nodes") or []:
            ip = str(node.get("ip") or "")
            host = ip_host.get(ip)
            if host:
                node["hostname"] = host
            elif not self._is_private(ip):
                node["hostname"] = None
                node["website_hint"] = True

        prediction: dict[str, Any] | None = None
        if self._model_loaded() and int(snapshot.get("node_count") or 0) > 0:
            try:
                from app.services.inference import inference_service
                prediction = inference_service.predict({}, snapshot)
                prediction["source"] = "live"
                prediction["window_id"] = snapshot.get("timestamp")
            except Exception as exc:
                logger.warning("live inference unavailable: %s", exc)
                prediction = {
                    "attack_type": None,
                    "confidence": None,
                    "risk_score": None,
                    "threat_level": "info",
                    "is_unknown": True,
                    "source": "live",
                    "message": "Prediction unavailable",
                    "error": str(exc),
                }
        elif int(snapshot.get("node_count") or 0) > 0:
            prediction = {
                "attack_type": None,
                "confidence": None,
                "risk_score": None,
                "threat_level": "info",
                "is_unknown": True,
                "source": "live",
                "message": "Prediction unavailable",
            }

        # Annotate node risk from window-level prediction (no fake per-node attacks).
        if prediction and prediction.get("risk_score") is not None:
            risk = float(prediction["risk_score"])
            for node in snapshot.get("nodes") or []:
                node["risk_score"] = risk
                if risk >= 0.75:
                    node["status"] = "compromised"
                elif risk >= 0.45:
                    node["status"] = "suspicious"
                else:
                    node["status"] = "online"
        else:
            for node in snapshot.get("nodes") or []:
                node.setdefault("risk_score", 0.1)
                node.setdefault("status", "online")

        self._window_seq += 1
        entry = {
            "seq": self._window_seq,
            "timestamp": snapshot.get("timestamp"),
            "node_count": snapshot.get("node_count"),
            "edge_count": snapshot.get("edge_count"),
            "prediction": prediction,
            "snapshot": snapshot,
        }
        self._windows.append(entry)
        self._latest = snapshot
        self._prediction = prediction
        self._last_update = datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _is_private(ip: str) -> bool:
        return (
            ip.startswith("10.")
            or ip.startswith("192.168.")
            or ip.startswith("172.16.")
            or ip.startswith("172.17.")
            or ip.startswith("172.18.")
            or ip.startswith("172.19.")
            or ip.startswith("172.2")
            or ip.startswith("127.")
            or ip == "::1"
        )


live_manager = LiveManager()
