"""Advanced evaluation metrics (Phase 5).

Computes ROC / precision-recall curve points, class distribution and model
artefact statistics. Used during training (_comprehensive_metrics) and exposed
via GET /api/v1/evaluation for the Performance Hub UI.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
from sklearn.metrics import precision_recall_curve, roc_curve
from sklearn.preprocessing import label_binarize

from app.models.tgnn import ATTACK_TYPES

MAX_CURVE_POINTS = 48


def _downsample(xs: list[float], ys: list[float], max_points: int = MAX_CURVE_POINTS) -> tuple[list[float], list[float]]:
    if len(xs) <= max_points:
        return xs, ys
    idx = np.linspace(0, len(xs) - 1, max_points).astype(int)
    return [xs[i] for i in idx], [ys[i] for i in idx]


def roc_curves(
    y_true: list[int],
    y_prob: np.ndarray | None,
    *,
    class_labels: list[str] | None = None,
) -> dict[str, list[dict[str, float]]]:
    """One-vs-rest ROC curve points per class present in y_true."""
    labels = class_labels or list(ATTACK_TYPES)
    if y_prob is None or not y_true:
        return {}

    present = sorted(set(y_true))
    if len(present) < 2:
        return {}

    out: dict[str, list[dict[str, float]]] = {}
    for cls_idx in present:
        name = labels[cls_idx] if cls_idx < len(labels) else str(cls_idx)
        binary_true = [1 if y == cls_idx else 0 for y in y_true]
        scores = y_prob[:, cls_idx] if y_prob.shape[1] > cls_idx else y_prob[:, 0]
        try:
            fpr, tpr, _ = roc_curve(binary_true, scores)
            fpr_l, tpr_l = _downsample(fpr.tolist(), tpr.tolist())
            out[name] = [
                {"fpr": round(float(f), 4), "tpr": round(float(t), 4)}
                for f, t in zip(fpr_l, tpr_l)
            ]
        except Exception:
            continue
    return out


def pr_curves(
    y_true: list[int],
    y_prob: np.ndarray | None,
    *,
    class_labels: list[str] | None = None,
) -> dict[str, list[dict[str, float]]]:
    """One-vs-rest precision-recall curve points per class."""
    labels = class_labels or list(ATTACK_TYPES)
    if y_prob is None or not y_true:
        return {}

    out: dict[str, list[dict[str, float]]] = {}
    for cls_idx in sorted(set(y_true)):
        name = labels[cls_idx] if cls_idx < len(labels) else str(cls_idx)
        binary_true = [1 if y == cls_idx else 0 for y in y_true]
        scores = y_prob[:, cls_idx] if y_prob.shape[1] > cls_idx else y_prob[:, 0]
        try:
            precision, recall, _ = precision_recall_curve(binary_true, scores)
            rc_l, pr_l = _downsample(recall.tolist(), precision.tolist())
            out[name] = [
                {"recall": round(float(r), 4), "precision": round(float(p), 4)}
                for r, p in zip(rc_l, pr_l)
            ]
        except Exception:
            continue
    return out


def class_distribution(
    per_class: dict[str, Any] | None,
    *,
    class_labels: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Support counts per attack class for bar charts."""
    labels = class_labels or list(ATTACK_TYPES)
    per_class = per_class or {}
    rows: list[dict[str, Any]] = []
    for name in labels:
        info = per_class.get(name) or {}
        count = int(info.get("support", 0) or 0)
        if count > 0:
            rows.append({"class": name, "count": count})
    # Include any class not in ATTACK_TYPES
    for name, info in per_class.items():
        if name not in labels and isinstance(info, dict):
            count = int(info.get("support", 0) or 0)
            if count > 0:
                rows.append({"class": name, "count": count})
    return sorted(rows, key=lambda r: r["count"], reverse=True)


def model_artifacts(model_path: Path) -> dict[str, Any]:
    """Checkpoint size and optional parameter count metadata."""
    info: dict[str, Any] = {
        "model_size_bytes": 0,
        "model_size_mb": 0.0,
    }
    if model_path.exists():
        size = model_path.stat().st_size
        info["model_size_bytes"] = size
        info["model_size_mb"] = round(size / (1024 * 1024), 3)
    return info


def enrich_evaluation(
    base: dict[str, Any],
    y_true: list[int],
    y_prob: np.ndarray | None,
    *,
    class_labels: list[str] | None = None,
) -> dict[str, Any]:
    """Attach curve + distribution data to a comprehensive metrics dict."""
    labels = class_labels or list(ATTACK_TYPES)
    enriched = dict(base)
    enriched["roc_curves"] = roc_curves(y_true, y_prob, class_labels=labels)
    enriched["pr_curves"] = pr_curves(y_true, y_prob, class_labels=labels)
    enriched["class_distribution"] = class_distribution(
        enriched.get("per_class"), class_labels=labels
    )
    return enriched


def build_evaluation_payload(checkpoint: dict[str, Any], model_path: Path) -> dict[str, Any]:
    """Full evaluation package for API / UI consumption."""
    metrics = checkpoint.get("metrics") or {}
    test = metrics.get("test") or {}
    artifacts = model_artifacts(model_path)

    history = metrics.get("history") or []
    learning_curve = [
        {
            "epoch": h.get("epoch"),
            "train_loss": h.get("train_loss"),
            "val_loss": h.get("val_loss"),
            "train_accuracy": h.get("train_accuracy"),
            "val_accuracy": h.get("val_accuracy"),
            "precision": h.get("precision"),
            "recall": h.get("recall"),
            "f1": h.get("f1"),
            "learning_rate": h.get("learning_rate"),
        }
        for h in history
        if isinstance(h, dict)
    ]

    return {
        "model_loaded": True,
        "architecture": checkpoint.get("architecture"),
        "dataset_id": checkpoint.get("dataset_id"),
        "trained_at": checkpoint.get("trained_at"),
        "graph_strategy": checkpoint.get("graph_strategy") or metrics.get("graph_strategy"),
        "graph_params": checkpoint.get("graph_params") or metrics.get("graph_params"),
        "feature_set": checkpoint.get("feature_set") or metrics.get("feature_set"),
        "headline": {
            "accuracy": metrics.get("accuracy"),
            "precision": metrics.get("precision"),
            "recall": metrics.get("recall"),
            "f1": metrics.get("f1"),
            "macro_f1": metrics.get("macro_f1"),
            "weighted_f1": metrics.get("weighted_f1"),
            "roc_auc": metrics.get("roc_auc") or test.get("roc_auc"),
            "train_loss": metrics.get("train_loss"),
            "val_loss": metrics.get("val_loss"),
            "best_epoch": metrics.get("best_epoch"),
        },
        "macro": {
            "precision": metrics.get("macro_precision") or test.get("macro_precision"),
            "recall": metrics.get("macro_recall") or test.get("macro_recall"),
            "f1": metrics.get("macro_f1") or test.get("macro_f1"),
        },
        "weighted": {
            "precision": test.get("precision") or metrics.get("precision"),
            "recall": test.get("recall") or metrics.get("recall"),
            "f1": test.get("f1") or metrics.get("f1"),
        },
        "test": test,
        "validation": metrics.get("validation") or {},
        "confusion_matrix": metrics.get("confusion_matrix"),
        "class_labels": metrics.get("class_labels") or list(ATTACK_TYPES),
        "per_class": metrics.get("per_class") or {},
        "class_distribution": metrics.get("class_distribution") or class_distribution(
            metrics.get("per_class")
        ),
        "roc_curves": metrics.get("roc_curves") or {},
        "pr_curves": metrics.get("pr_curves") or {},
        "learning_curve": learning_curve,
        "training_time_sec": metrics.get("training_time_sec"),
        "inference_time_ms": metrics.get("inference_time_ms"),
        "graph_stats": metrics.get("graph_stats") or {},
        "split": metrics.get("split") or {},
        "model_comparison": metrics.get("model_comparison"),
        **artifacts,
    }
