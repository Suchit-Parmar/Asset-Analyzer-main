"""Automatic model comparison (Phase 12, step 6).

Compares the current **active** model against a **candidate** using their stored
evaluation metrics and returns a side-by-side table plus a recommendation. The
guiding rule of the whole platform is enforced here:

    *A better model is never replaced by a worse one, and nothing is activated
     automatically — comparison only produces a recommendation for the user.*

Beyond the headline metrics we derive macro False-Positive-Rate (FPR) and
False-Negative-Rate (FNR) from the confusion matrix, plus training/inference
time, memory (checkpoint size) and graph density, because in an IDS a lower FPR
can matter more than a marginally higher accuracy.
"""

from __future__ import annotations

from typing import Any

import numpy as np


def _cm_rates(cm: list[list[int]] | None) -> dict[str, float | None]:
    """Macro False-Positive / False-Negative rate from a confusion matrix."""
    if not cm:
        return {"fpr": None, "fnr": None}
    m = np.array(cm, dtype=float)
    if m.ndim != 2 or m.shape[0] != m.shape[1] or m.sum() == 0:
        return {"fpr": None, "fnr": None}
    total = m.sum()
    fprs, fnrs = [], []
    for i in range(m.shape[0]):
        tp = m[i, i]
        fn = m[i, :].sum() - tp
        fp = m[:, i].sum() - tp
        tn = total - tp - fn - fp
        # Only average over classes that actually occur (support > 0).
        if (tp + fn) > 0:
            fnrs.append(fn / (fn + tp))
        if (fp + tn) > 0:
            fprs.append(fp / (fp + tn))
    return {
        "fpr": round(float(np.mean(fprs)), 4) if fprs else None,
        "fnr": round(float(np.mean(fnrs)), 4) if fnrs else None,
    }


def _extract(metrics: dict[str, Any], size_bytes: int | None = None) -> dict[str, Any]:
    metrics = metrics or {}
    test = metrics.get("test") or {}
    cm = metrics.get("confusion_matrix") or test.get("confusion_matrix")
    rates = _cm_rates(cm)
    return {
        "accuracy": test.get("accuracy", metrics.get("accuracy")),
        "precision": test.get("precision", metrics.get("precision")),
        "recall": test.get("recall", metrics.get("recall")),
        "f1": test.get("f1", metrics.get("f1")),
        "macro_f1": metrics.get("macro_f1") or test.get("macro_f1"),
        "roc_auc": metrics.get("roc_auc") or test.get("roc_auc"),
        "fpr": rates["fpr"],
        "fnr": rates["fnr"],
        "training_time_sec": metrics.get("training_time_sec"),
        "inference_time_ms": metrics.get("inference_time_ms"),
        "graph_density": (metrics.get("graph_stats") or {}).get("avg_density"),
        "memory_bytes": size_bytes,
    }


def _num(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def compare(
    active: dict[str, Any],
    candidate: dict[str, Any],
    *,
    active_size: int | None = None,
    candidate_size: int | None = None,
    margin: float = 0.0,
) -> dict[str, Any]:
    """Return a comparison report + recommendation (no side effects)."""
    a = _extract(active, active_size)
    c = _extract(candidate, candidate_size)

    # "Higher is better" for most metrics; FPR/FNR/time/memory are inverted.
    higher_better = {"accuracy", "precision", "recall", "f1", "macro_f1", "roc_auc"}
    lower_better = {"fpr", "fnr", "training_time_sec", "inference_time_ms", "memory_bytes"}

    rows: list[dict[str, Any]] = []
    for key in [
        "accuracy", "precision", "recall", "f1", "macro_f1", "roc_auc",
        "fpr", "fnr", "training_time_sec", "inference_time_ms",
        "graph_density", "memory_bytes",
    ]:
        av, cv = _num(a.get(key)), _num(c.get(key))
        delta = (cv - av) if (av is not None and cv is not None) else None
        if delta is None or key not in (higher_better | lower_better):
            better = None
        elif key in higher_better:
            better = "candidate" if delta > 0 else ("active" if delta < 0 else "tie")
        else:
            better = "candidate" if delta < 0 else ("active" if delta > 0 else "tie")
        rows.append({
            "metric": key,
            "active": a.get(key),
            "candidate": c.get(key),
            "delta": round(delta, 4) if delta is not None else None,
            "better": better,
        })

    # Decision: candidate must improve headline F1 (test) by >= margin without a
    # material accuracy regression. Conservative on purpose.
    a_f1, c_f1 = _num(a.get("f1")), _num(c.get("f1"))
    a_acc, c_acc = _num(a.get("accuracy")), _num(c.get("accuracy"))

    if c_f1 is None:
        candidate_better = False
        reason = "Candidate has no evaluation metrics."
    elif a_f1 is None:
        candidate_better = True
        reason = "No active model metrics available; candidate can be promoted after review."
    else:
        f1_gain = c_f1 - a_f1
        acc_regression = (a_acc - c_acc) if (a_acc is not None and c_acc is not None) else 0.0
        candidate_better = f1_gain >= margin and acc_regression <= 0.02
        if candidate_better:
            reason = f"Candidate F1 improves by {f1_gain:+.4f} with no material accuracy regression."
        else:
            reason = (
                f"Candidate does not clearly beat the active model (F1 delta {f1_gain:+.4f}). "
                "Keeping the current model."
            )

    return {
        "rows": rows,
        "active": a,
        "candidate": c,
        "candidate_better": bool(candidate_better),
        "recommendation": "promote_candidate" if candidate_better else "keep_active",
        "reason": reason,
        "note": "Recommendation only — the active model is never replaced without explicit user approval.",
    }


def compare_from_metrics(*args, **kwargs):  # backwards-friendly alias
    return compare(*args, **kwargs)
