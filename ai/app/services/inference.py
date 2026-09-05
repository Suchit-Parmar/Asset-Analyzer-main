"""Model inference service — loads Phase 2 TGNN checkpoint for live predictions."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import numpy as np
import torch
import torch.nn.functional as F

from app.graph.builder import (
    NODE_FEATURE_DIM,
    endpoint_feature_name,
    is_reserved_endpoint_dim,
)
from app.models.tgnn import TGNNModel, ATTACK_STAGES, ATTACK_TYPES, STAGE_TRANSITIONS


def _resolve_model_dir() -> Path:
    env = os.environ.get("MODEL_DIR")
    if env:
        path = Path(env).expanduser()
        # If relative path like ./ai/models is used while cwd is ai/, fall back to sibling models/
        if not path.is_absolute():
            candidate = path.resolve()
            if candidate.exists():
                return candidate
            local = Path(__file__).resolve().parents[2] / "models"
            if local.exists():
                return local
            return candidate
        return path.resolve()
    return Path(__file__).resolve().parents[2] / "models"


MODEL_DIR = _resolve_model_dir()

MITRE_MAP = {
    "DDoS": ("Impact", "T1498"),
    "Probe": ("Reconnaissance", "T1046"),
    "R2L": ("Initial Access", "T1078"),
    "U2R": ("Privilege Escalation", "T1068"),
    "Botnet": ("Command and Control", "T1071"),
    "Normal": ("None", "None"),
    "Generic": ("Execution", "T1204"),
    "Exploits": ("Initial Access", "T1190"),
    "Fuzzers": ("Discovery", "T1046"),
    "DoS": ("Impact", "T1499"),
    "Reconnaissance": ("Reconnaissance", "T1595"),
    "Brute Force": ("Credential Access", "T1110"),
    "Web Attack": ("Initial Access", "T1190"),
    "Infiltration": ("Lateral Movement", "T1021"),
    "Heartbleed": ("Privilege Escalation", "T1068"),
}

THREAT_LEVELS = {
    "Normal": "low",
    "DDoS": "critical",
    "Probe": "medium",
    "R2L": "high",
    "U2R": "critical",
    "Botnet": "high",
    "Generic": "high",
    "Exploits": "high",
    "Fuzzers": "medium",
    "DoS": "critical",
    "Reconnaissance": "medium",
    "Brute Force": "high",
    "Web Attack": "high",
    "Infiltration": "critical",
    "Heartbleed": "critical",
}


# Below this attack-confidence the model is treated as unsure / possibly unknown
# traffic and the prediction is queued for human review (active learning).
UNKNOWN_CONFIDENCE = 0.35


def _to_1d_probs(tensor: torch.Tensor) -> np.ndarray:
    arr = tensor.detach().float().cpu().numpy()
    arr = np.atleast_1d(arr).reshape(-1)
    return arr


class InferenceService:
    def __init__(self):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model: TGNNModel | None = None
        self.model_path = MODEL_DIR / "tgnn_model.pt"
        self.metadata: dict[str, Any] = {}
        self._load_model()

    def _load_model(self) -> None:
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        self.model_path = MODEL_DIR / "tgnn_model.pt"

        architecture = "gat"
        hidden_dim = 64
        node_features = NODE_FEATURE_DIM
        state_dict = None

        if self.model_path.exists():
            checkpoint = torch.load(
                self.model_path, map_location=self.device, weights_only=False
            )
            if not isinstance(checkpoint, dict) or "model_state" not in checkpoint:
                raise RuntimeError(
                    f"Invalid checkpoint at {self.model_path}: expected dict with model_state"
                )

            architecture = str(checkpoint.get("architecture", "gat"))
            hidden_dim = int(checkpoint.get("hidden_dim", 64))
            node_features = int(checkpoint.get("node_features", NODE_FEATURE_DIM))
            state_dict = checkpoint["model_state"]

            metrics = checkpoint.get("metrics") or {}
            # Drop bulky history from in-memory metadata
            metrics_summary = {
                k: v
                for k, v in metrics.items()
                if k != "history"
            }
            self.metadata = {
                "architecture": architecture,
                "hidden_dim": hidden_dim,
                "node_features": node_features,
                "dataset_id": checkpoint.get("dataset_id"),
                "trained_at": checkpoint.get("trained_at"),
                "metrics": metrics_summary,
                "attack_types": checkpoint.get("attack_types", ATTACK_TYPES),
                "attack_stages": checkpoint.get("attack_stages", ATTACK_STAGES),
                "graph_strategy": checkpoint.get("graph_strategy")
                or metrics.get("graph_strategy"),
                "graph_params": checkpoint.get("graph_params")
                or metrics.get("graph_params"),
                "feature_set": checkpoint.get("feature_set")
                or metrics.get("feature_set"),
                "model_path": str(self.model_path),
                "model_size_bytes": self.model_path.stat().st_size,
                "model_size_mb": round(self.model_path.stat().st_size / (1024 * 1024), 3),
            }
            print(
                f"[inference] Loaded checkpoint {self.model_path} "
                f"(arch={architecture}, hidden={hidden_dim}, feats={node_features})"
            )
        else:
            self.metadata = {
                "architecture": architecture,
                "hidden_dim": hidden_dim,
                "node_features": node_features,
                "model_path": str(self.model_path),
                "warning": "No trained checkpoint found; using randomly initialized weights",
            }
            print(f"[inference] No trained model at {self.model_path}; using init weights")

        self.model = TGNNModel(
            node_features=node_features,
            hidden_dim=hidden_dim,
            architecture=architecture,
        )
        if state_dict is not None:
            # strict=False so older checkpoints without the feature-normalization
            # buffers still load (buffers fall back to identity defaults).
            self.model.load_state_dict(state_dict, strict=False)
        self.model.to(self.device)
        self.model.eval()

    def reload(self) -> dict[str, Any]:
        """Reload checkpoint from disk (e.g. after retraining)."""
        self._load_model()
        return self.get_info()

    def get_info(self) -> dict[str, Any]:
        return {
            "model_loaded": self.is_loaded,
            "device": str(self.device),
            "gpu_available": torch.cuda.is_available(),
            **self.metadata,
        }

    @property
    def is_loaded(self) -> bool:
        return self.model is not None and self.model_path.exists()

    def predict(
        self,
        features: dict[str, Any] | None = None,
        graph_snapshot: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if self.model is None:
            raise RuntimeError("Model not initialized")
        if not self.is_loaded:
            raise RuntimeError(
                f"Trained TGNN checkpoint not found at {self.model_path}. "
                "Complete Phase 2 training before inference."
            )

        features = features or {}
        x, edge_index = self._prepare_tensors(features, graph_snapshot)

        with torch.no_grad():
            outputs = self.model(x, edge_index)

        attack_probs = _to_1d_probs(F.softmax(outputs["attack_logits"], dim=-1).squeeze())
        stage_probs = _to_1d_probs(F.softmax(outputs["stage_logits"], dim=-1).squeeze())
        next_stage_probs = _to_1d_probs(
            F.softmax(outputs["next_stage_logits"], dim=-1).squeeze()
        )
        risk_raw = outputs["risk_score"].squeeze()
        risk_score = float(risk_raw.detach().cpu().item()) if risk_raw.numel() else 0.0
        compromise_prob = _to_1d_probs(
            F.softmax(outputs["compromise_logits"], dim=-1).squeeze()
        )

        attack_idx = int(np.argmax(attack_probs))
        stage_idx = int(np.argmax(stage_probs))
        next_stage_idx = int(np.argmax(next_stage_probs))

        attack_types = list(self.metadata.get("attack_types") or ATTACK_TYPES)
        attack_stages = list(self.metadata.get("attack_stages") or ATTACK_STAGES)

        attack_type = attack_types[min(attack_idx, len(attack_types) - 1)]
        attack_stage = attack_stages[min(stage_idx, len(attack_stages) - 1)]
        predicted_next_stage = attack_stages[min(next_stage_idx, len(attack_stages) - 1)]
        confidence = float(np.max(attack_probs))
        probability = float(np.max(stage_probs))
        threat_level = THREAT_LEVELS.get(attack_type, "medium")
        mitre_tactic, mitre_technique = MITRE_MAP.get(attack_type, ("Unknown", "T0000"))

        attention = outputs.get("attention_weights")
        node_importance = self._compute_node_importance(outputs["node_embeddings"], attention)

        is_compromised = bool(len(compromise_prob) > 1 and compromise_prob[1] > 0.5)
        is_unknown = bool(confidence < UNKNOWN_CONFIDENCE)

        # Explainable AI (Phase 12): top contributing features, graph statistics
        # and a plain-language reasoning summary for every prediction.
        top_features = self._feature_importance(x)
        graph_statistics = self._graph_statistics(x, edge_index)
        reasoning = self._reasoning_summary(
            attack_type, attack_stage, predicted_next_stage,
            confidence, risk_score, threat_level, top_features, is_unknown,
        )

        result = {
            "attack_type": attack_type,
            "attack_stage": attack_stage,
            "predicted_next_stage": predicted_next_stage,
            "threat_level": threat_level,
            "probability": round(probability, 4),
            "confidence": round(confidence, 4),
            "risk_score": round(risk_score, 4),
            "is_compromised": is_compromised,
            "is_unknown": is_unknown,
            "mitre_tactic": mitre_tactic,
            "mitre_technique": mitre_technique,
            "all_probabilities": {
                attack_types[i]: round(float(attack_probs[i]), 4)
                for i in range(min(len(attack_probs), len(attack_types)))
            },
            "stage_probabilities": {
                attack_stages[i]: round(float(stage_probs[i]), 4)
                for i in range(min(len(stage_probs), len(attack_stages)))
            },
            "model": {
                "architecture": self.metadata.get("architecture"),
                "dataset_id": self.metadata.get("dataset_id"),
                "trained_at": self.metadata.get("trained_at"),
            },
            "explanation": {
                "node_importance": node_importance,
                "top_features": top_features,
                "feature_importance": top_features,
                "graph_statistics": graph_statistics,
                "top_attack_type": attack_type,
                "predicted_progression": f"{attack_stage} -> {predicted_next_stage}",
                "expected_next": STAGE_TRANSITIONS.get(attack_stage, attack_stage),
                "reasoning": reasoning,
            },
        }

        # SOC Response Engine (Phase 8): actionable containment + detection
        # artefacts (MITRE, kill-chain, Sigma/YARA/Suricata/Snort, firewall,
        # isolation, response playbook). Best-effort — never breaks inference.
        try:
            from app.services.soc_response import soc_engine

            result["soc_response"] = soc_engine.from_prediction(
                result,
                source_ip=features.get("source_ip") or features.get("src_ip"),
                target_ip=features.get("target_ip") or features.get("dst_ip"),
                protocol=features.get("protocol"),
                port=features.get("dst_port") or features.get("port"),
            )
        except Exception:
            pass

        # Confidence-based learning (Phase 12): queue low-confidence / unknown
        # predictions for human review. Best-effort — never breaks inference.
        try:
            from app.services.review_queue import review_queue

            review_queue.record_prediction({
                "confidence": confidence,
                "attack_type": attack_type,
                "threat_level": threat_level,
                "is_unknown": is_unknown,
                "features": {f["feature"]: f["value"] for f in top_features[:6]},
                "graph": graph_statistics,
            })
        except Exception:
            pass

        return result

    def predict_batch(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for record in records:
            if "features" in record or "graph_snapshot" in record:
                results.append(
                    self.predict(
                        record.get("features") or {},
                        record.get("graph_snapshot"),
                    )
                )
            else:
                results.append(self.predict(record))
        return results

    def _prepare_tensors(
        self,
        features: dict[str, Any],
        graph_snapshot: dict[str, Any] | None,
    ) -> tuple[torch.Tensor, torch.Tensor]:
        expected_dim = int(self.metadata.get("node_features") or NODE_FEATURE_DIM)

        if graph_snapshot and "node_features" in graph_snapshot:
            node_features = graph_snapshot["node_features"]
            edge_index = graph_snapshot.get("edge_index", [[0], [0]])
            x = torch.tensor(node_features, dtype=torch.float32, device=self.device)
            if x.dim() == 1:
                x = x.unsqueeze(0)
            if x.size(0) == 0:
                x = torch.zeros((1, expected_dim), dtype=torch.float32, device=self.device)
            if x.size(1) != expected_dim:
                if x.size(1) < expected_dim:
                    pad = torch.zeros(
                        (x.size(0), expected_dim - x.size(1)),
                        dtype=torch.float32,
                        device=self.device,
                    )
                    x = torch.cat([x, pad], dim=1)
                else:
                    x = x[:, :expected_dim]

            ei = torch.tensor(edge_index, dtype=torch.long, device=self.device)
            if ei.dim() == 2 and ei.size(0) != 2:
                ei = ei.t().contiguous()
            if ei.numel() == 0 or ei.dim() != 2:
                ei = torch.tensor([[0], [0]], dtype=torch.long, device=self.device)
            # Clamp edge indices into valid node range
            max_idx = max(int(x.size(0)) - 1, 0)
            ei = ei.clamp(0, max_idx)

            # Phase 3: apply the checkpoint's feature mask so inference matches
            # the training-time feature selection.
            fs = self.metadata.get("feature_set")
            if fs:
                from app.services.feature_selection import mask_vector, vector_kind_for_strategy

                strategy = self.metadata.get("graph_strategy")
                kind = vector_kind_for_strategy(strategy)
                masked = [mask_vector(row, fs, kind=kind) for row in x.detach().cpu().tolist()]
                x = torch.tensor(masked, dtype=torch.float32, device=self.device)
        else:
            feat_vec = [
                float(features.get("duration", 0) or 0),
                float(features.get("src_bytes", features.get("sbytes", 0)) or 0),
                float(features.get("dst_bytes", features.get("dbytes", 0)) or 0),
                float(features.get("src_packets", features.get("spkts", 1)) or 1),
                float(features.get("dst_packets", features.get("dpkts", 1)) or 1),
                float(features.get("num_failed_logins", 0) or 0),
                float(features.get("count", features.get("ct_srv_src", 1)) or 1),
                float(features.get("srv_count", features.get("ct_srv_dst", 1)) or 1),
                float(features.get("serror_rate", 0) or 0),
                float(features.get("same_srv_rate", 0.5) or 0.5),
                float(features.get("dst_host_count", 50) or 50),
                float(hash(str(features.get("protocol", "tcp"))) % 100),
                float(hash(str(features.get("service", "http"))) % 100),
                float(features.get("logged_in", 0) or 0),
                float(features.get("num_compromised", 0) or 0),
                float(features.get("root_shell", 0) or 0),
            ]
            if len(feat_vec) < expected_dim:
                feat_vec.extend([0.0] * (expected_dim - len(feat_vec)))
            else:
                feat_vec = feat_vec[:expected_dim]
            fs = self.metadata.get("feature_set")
            if fs:
                from app.services.feature_selection import mask_vector

                feat_vec = mask_vector(feat_vec, fs, kind="inference")
            x = torch.tensor([feat_vec], dtype=torch.float32, device=self.device)
            ei = torch.tensor([[0], [0]], dtype=torch.long, device=self.device)

        return x, ei

    def _feature_importance(self, x: torch.Tensor) -> list[dict[str, Any]]:
        """Rank active endpoint node features by standardized magnitude (XAI)."""
        try:
            mean = self.model.feat_mean.to(x.device) if hasattr(self.model, "feat_mean") else 0.0
            std = self.model.feat_std.to(x.device) if hasattr(self.model, "feat_std") else 1.0
            z = (x - mean) / (std + 1e-6)
            scores = z.abs().mean(dim=0).detach().cpu().numpy()
        except Exception:
            scores = x.abs().mean(dim=0).detach().cpu().numpy()
        raw_means = x.mean(dim=0).detach().cpu().numpy()
        active_scores = [
            float(scores[i])
            for i in range(min(len(scores), NODE_FEATURE_DIM))
            if not is_reserved_endpoint_dim(i)
        ]
        total = float(np.sum(active_scores)) or 1.0
        feats = []
        for i, score in enumerate(scores):
            if is_reserved_endpoint_dim(i):
                continue
            feats.append({
                "feature": endpoint_feature_name(i),
                "importance": round(float(score / total), 4),
                "value": round(float(raw_means[i]), 4),
                "index": i,
            })
        feats.sort(key=lambda f: f["importance"], reverse=True)
        return feats[:8]

    def _graph_statistics(self, x: torch.Tensor, edge_index: torch.Tensor) -> dict[str, Any]:
        nodes = int(x.size(0))
        edges = int(edge_index.size(1)) if edge_index.dim() == 2 else 0
        max_edges = nodes * (nodes - 1)
        density = round(edges / max_edges, 4) if max_edges > 0 else 0.0
        avg_degree = round((edges / nodes), 3) if nodes > 0 else 0.0
        return {
            "node_count": nodes,
            "edge_count": edges,
            "density": density,
            "avg_degree": avg_degree,
        }

    def _reasoning_summary(
        self,
        attack_type: str,
        attack_stage: str,
        next_stage: str,
        confidence: float,
        risk_score: float,
        threat_level: str,
        top_features: list[dict[str, Any]],
        is_unknown: bool,
    ) -> str:
        top = ", ".join(f["feature"] for f in top_features[:3]) or "graph structure"
        if is_unknown:
            return (
                f"Low-confidence prediction ({confidence:.0%}) — traffic may be an unknown "
                f"pattern. Closest match is '{attack_type}'. Queued for human review. "
                f"Key signals: {top}."
            )
        if attack_type.lower() in ("normal",):
            return (
                f"Traffic classified as benign with {confidence:.0%} confidence "
                f"(threat: {threat_level}). Dominant signals: {top}."
            )
        return (
            f"Predicted '{attack_type}' ({threat_level} threat) at stage '{attack_stage}' "
            f"with {confidence:.0%} confidence and risk {risk_score:.2f}. Likely next stage: "
            f"'{next_stage}'. Key contributing features: {top}."
        )

    def _compute_node_importance(
        self,
        embeddings: torch.Tensor,
        attention: torch.Tensor | None,
    ) -> list[dict[str, Any]]:
        norms = embeddings.norm(dim=-1).cpu().numpy()
        total = float(norms.sum()) or 1.0
        importance = []
        for i, score in enumerate(norms):
            entry: dict[str, Any] = {
                "node_index": i,
                "importance": round(float(score / total), 4),
                "type": "node",
            }
            if attention is not None:
                entry["attention_weight"] = round(float(attention.mean().cpu().item()), 4)
            importance.append(entry)
        importance.sort(key=lambda x: x["importance"], reverse=True)
        return importance[:10]


inference_service = InferenceService()
