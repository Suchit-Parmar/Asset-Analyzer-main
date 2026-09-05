"""AI explainability service using attention weights and SHAP."""

from __future__ import annotations

from typing import Any

import numpy as np
import torch

from app.graph.builder import (
    NODE_FEATURE_DIM,
    endpoint_feature_name,
    is_reserved_endpoint_dim,
)
from app.services.inference import inference_service


class ExplainabilityService:
    def explain(
        self,
        node_id: str,
        graph_snapshot: dict[str, Any],
    ) -> dict[str, Any]:
        if inference_service.model is None:
            raise RuntimeError("Model not loaded")

        x, edge_index = inference_service._prepare_tensors({}, graph_snapshot)

        inference_service.model.eval()
        with torch.no_grad():
            outputs = inference_service.model(x, edge_index)

        node_importance = inference_service._compute_node_importance(
            outputs["node_embeddings"],
            outputs.get("attention_weights"),
        )

        edge_importance = self._compute_edge_importance(
            graph_snapshot.get("edges", []),
            node_importance,
        )

        target_node = self._find_node(node_id, graph_snapshot.get("nodes", []))
        target_idx = self._find_node_index(node_id, graph_snapshot.get("nodes", []))

        integrated_grads = self._integrated_gradients(x, edge_index, target_idx)

        attack_probs = torch.softmax(outputs["attack_logits"], dim=-1).squeeze().cpu().numpy()
        stage_probs = torch.softmax(outputs["stage_logits"], dim=-1).squeeze().cpu().numpy()

        reasoning = self._generate_reasoning(
            target_node, node_importance, edge_importance, attack_probs, stage_probs,
        )
        reasoning_tree = self._build_reasoning_tree(
            target_node, node_importance, edge_importance, attack_probs, stage_probs,
            integrated_grads,
        )
        graph_heatmap = self._build_graph_heatmap(
            graph_snapshot.get("nodes", []),
            node_importance,
            edge_importance,
        )

        return {
            "node_id": node_id,
            "target_node": target_node,
            "node_importance": node_importance,
            "edge_importance": edge_importance,
            "attention_weights": self._format_attention(outputs.get("attention_weights")),
            "integrated_gradients": integrated_grads,
            "shap_values": self._approximate_shap(x, edge_index),
            "reasoning": reasoning,
            "reasoning_tree": reasoning_tree,
            "graph_heatmap": graph_heatmap,
            "attack_probabilities": {
                str(i): round(float(p), 4) for i, p in enumerate(attack_probs)
            },
            "stage_probabilities": {
                str(i): round(float(p), 4) for i, p in enumerate(stage_probs)
            },
        }

    def _compute_edge_importance(
        self,
        edges: list[dict],
        node_importance: list[dict],
    ) -> list[dict[str, Any]]:
        node_scores = {n["node_index"]: n["importance"] for n in node_importance}
        edge_scores = []
        for i, edge in enumerate(edges[:50]):
            src_imp = node_scores.get(i, 0.1)
            score = src_imp * (edge.get("packets", 1) / max(edge.get("bytes", 1), 1))
            edge_scores.append({
                "edge_index": i,
                "source": edge.get("source"),
                "target": edge.get("target"),
                "protocol": edge.get("protocol"),
                "importance": round(float(score), 4),
                "type": "edge",
            })
        edge_scores.sort(key=lambda x: x["importance"], reverse=True)
        return edge_scores[:15]

    def _integrated_gradients(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        target_idx: int,
        steps: int = 20,
    ) -> list[dict[str, Any]]:
        if inference_service.model is None:
            return []

        baseline = torch.zeros_like(x)
        grads = []
        for step in range(steps):
            alpha = step / steps
            interpolated = baseline + alpha * (x - baseline)
            interpolated.requires_grad_(True)
            outputs = inference_service.model(interpolated, edge_index)
            score = outputs["risk_score"].sum()
            score.backward()
            if interpolated.grad is not None:
                grads.append(interpolated.grad.detach())

        if not grads:
            return []

        avg_grads = torch.stack(grads).mean(dim=0)
        ig = (x - baseline) * avg_grads
        ig_np = np.atleast_2d(ig.detach().cpu().numpy())
        if ig_np.ndim > 2:
            ig_np = ig_np.reshape(ig_np.shape[0], -1)
        # Aggregate per-feature attribution across nodes (target row when single-node).
        row = ig_np[target_idx] if 0 <= target_idx < ig_np.shape[0] else ig_np.mean(axis=0)
        if row.ndim > 1:
            row = row.reshape(-1)

        result = []
        for i, val in enumerate(row[:NODE_FEATURE_DIM]):
            if is_reserved_endpoint_dim(i):
                continue
            result.append({
                "feature": endpoint_feature_name(i),
                "importance": round(float(val), 4),
                "index": i,
                "method": "integrated_gradients",
            })
        result.sort(key=lambda x: abs(x["importance"]), reverse=True)
        return result

    def _approximate_shap(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
    ) -> list[dict[str, Any]]:
        if inference_service.model is None:
            return []

        baseline = torch.zeros_like(x)
        with torch.no_grad():
            base_out = inference_service.model(baseline, edge_index)
            base_score = base_out["risk_score"].item()

        shap_values = []
        active_dims = [
            i for i in range(min(NODE_FEATURE_DIM, int(x.size(-1))))
            if not is_reserved_endpoint_dim(i)
        ]

        for i in active_dims:
            perturbed = x.clone()
            perturbed[:, i] = 0
            with torch.no_grad():
                out = inference_service.model(perturbed, edge_index)
                delta = base_score - out["risk_score"].item()
            shap_values.append({
                "feature": endpoint_feature_name(i),
                "shap_value": round(float(delta), 4),
                "index": i,
                "method": "shap_approximation",
            })

        shap_values.sort(key=lambda x: abs(x["shap_value"]), reverse=True)
        return shap_values

    def _format_attention(self, attention: torch.Tensor | None) -> list[dict[str, Any]]:
        if attention is None:
            return []
        attn = attention.squeeze().cpu().numpy()
        if attn.ndim == 0:
            return [{"weight": round(float(attn), 4)}]
        flat = attn.flatten()
        return [
            {"head": i, "weight": round(float(w), 4)}
            for i, w in enumerate(flat[:8])
        ]

    def _find_node(self, node_id: str, nodes: list[dict]) -> dict | None:
        for node in nodes:
            if node.get("id") == node_id or node.get("ip") == node_id:
                return node
        return nodes[0] if nodes else None

    def _find_node_index(self, node_id: str, nodes: list[dict]) -> int:
        for i, node in enumerate(nodes):
            if node.get("id") == node_id or node.get("ip") == node_id:
                return i
        return 0

    def _generate_reasoning(
        self,
        target_node: dict | None,
        node_importance: list[dict],
        edge_importance: list[dict],
        attack_probs: np.ndarray,
        stage_probs: np.ndarray,
    ) -> str:
        top_node = node_importance[0] if node_importance else None
        top_edge = edge_importance[0] if edge_importance else None
        attack_idx = int(np.argmax(attack_probs))
        stage_idx = int(np.argmax(stage_probs))

        parts = [
            f"The model identified anomalous behavior with {attack_probs[attack_idx]*100:.1f}% attack confidence.",
            f"Current attack stage probability peaks at index {stage_idx} ({stage_probs[stage_idx]*100:.1f}%).",
        ]

        if target_node:
            parts.append(
                f"Target node {target_node.get('ip', 'unknown')} shows elevated "
                f"traffic: {target_node.get('packets', 0)} packets, "
                f"{target_node.get('connections', 0)} connections."
            )

        if top_node:
            parts.append(
                f"Highest node importance score ({top_node['importance']:.3f}) "
                f"at node index {top_node['node_index']} via GAT attention."
            )

        if top_edge:
            parts.append(
                f"Critical edge: {top_edge.get('source')} -> {top_edge.get('target')} "
                f"via {top_edge.get('protocol', 'unknown')} (importance: {top_edge['importance']:.3f})."
            )

        return " ".join(parts)

    def _build_reasoning_tree(
        self,
        target_node: dict | None,
        node_importance: list[dict],
        edge_importance: list[dict],
        attack_probs: np.ndarray,
        stage_probs: np.ndarray,
        integrated_grads: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Structured decision tree for the Explainability UI."""
        attack_idx = int(np.argmax(attack_probs))
        stage_idx = int(np.argmax(stage_probs))
        top_features = integrated_grads[:3] if integrated_grads else []

        root = {
            "id": "root",
            "label": "TGNN risk assessment",
            "detail": f"Attack confidence {attack_probs[attack_idx] * 100:.1f}%",
            "children": [
                {
                    "id": "attack",
                    "label": f"Predicted attack class #{attack_idx}",
                    "detail": f"Probability {attack_probs[attack_idx] * 100:.1f}%",
                    "children": [],
                },
                {
                    "id": "stage",
                    "label": f"Kill-chain stage #{stage_idx}",
                    "detail": f"Stage probability {stage_probs[stage_idx] * 100:.1f}%",
                    "children": [],
                },
            ],
        }

        if target_node:
            root["children"].append({
                "id": "target",
                "label": f"Target {target_node.get('ip', target_node.get('id', 'node'))}",
                "detail": (
                    f"{target_node.get('packets', 0)} packets · "
                    f"{target_node.get('connections', 0)} connections"
                ),
                "children": [],
            })

        if top_features:
            root["children"].append({
                "id": "features",
                "label": "Top integrated-gradient features",
                "detail": ", ".join(f["feature"] for f in top_features),
                "children": [
                    {
                        "id": f"feat-{i}",
                        "label": f["feature"],
                        "detail": f"IG score {f['importance']:.4f}",
                        "children": [],
                    }
                    for i, f in enumerate(top_features)
                ],
            })

        if node_importance:
            top = node_importance[0]
            root["children"].append({
                "id": "attention",
                "label": "GAT attention focus",
                "detail": f"Node index {top.get('node_index')} · score {top.get('importance', 0):.3f}",
                "children": [
                    {
                        "id": f"node-{n.get('node_index', i)}",
                        "label": n.get("label") or n.get("ip") or f"Node {n.get('node_index', i)}",
                        "detail": f"Importance {n.get('importance', 0):.3f}",
                        "children": [],
                    }
                    for i, n in enumerate(node_importance[:3])
                ],
            })

        if edge_importance:
            e = edge_importance[0]
            root["children"].append({
                "id": "edge",
                "label": "Critical communication edge",
                "detail": (
                    f"{e.get('source', '?')} → {e.get('target', '?')} "
                    f"({e.get('protocol', 'unknown')})"
                ),
                "children": [],
            })

        return [root]

    def _build_graph_heatmap(
        self,
        nodes: list[dict],
        node_importance: list[dict],
        edge_importance: list[dict],
    ) -> dict[str, Any]:
        """Node/edge intensity map for graph overlay visualization."""
        score_by_idx = {
            int(n.get("node_index", i)): float(n.get("importance", 0))
            for i, n in enumerate(node_importance)
        }
        max_node = max(score_by_idx.values(), default=1.0) or 1.0

        heat_nodes = []
        for i, node in enumerate(nodes[:80]):
            raw = score_by_idx.get(i, 0.0)
            heat_nodes.append({
                "id": node.get("id") or node.get("ip") or f"node-{i}",
                "ip": node.get("ip"),
                "label": node.get("label") or node.get("ip") or f"Node {i}",
                "importance": round(raw, 4),
                "intensity": round(min(1.0, raw / max_node), 4),
            })

        max_edge = max((e.get("importance", 0) for e in edge_importance), default=1.0) or 1.0
        heat_edges = [
            {
                "source": e.get("source"),
                "target": e.get("target"),
                "protocol": e.get("protocol"),
                "importance": e.get("importance", 0),
                "intensity": round(min(1.0, float(e.get("importance", 0)) / max_edge), 4),
            }
            for e in edge_importance[:30]
        ]

        return {
            "nodes": heat_nodes,
            "edges": heat_edges,
            "max_node_importance": round(max_node, 4),
            "max_edge_importance": round(max_edge, 4),
        }


explainability_service = ExplainabilityService()
