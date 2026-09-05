"""Concept-drift detection (Phase 12, step 3).

Drift is measured by comparing a *baseline* distribution (captured when a dataset
version was registered / a model was trained) against a *candidate* distribution
(new incoming traffic). Three complementary signals are produced:

  * Covariate shift – the input feature distributions move. Measured per numeric
    feature with the Population Stability Index (PSI) over baseline bin edges.
  * Label drift     – the attack-class mix changes. Measured with total-variation
    distance between the two label distributions.
  * Concept drift   – the input→label mapping degrades. Detected from a drop in
    model accuracy / prediction confidence on recent data (supplied by caller).

Thresholds follow the widely used PSI convention:
    PSI < 0.1  → no significant shift
    0.1–0.25   → moderate shift
    > 0.25     → significant shift

Retraining is only *recommended* when drift is significant. This module never
retrains or activates anything — it just reports.
"""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

from app.services.data_quality import find_label_column

PSI_MODERATE = 0.1
PSI_SIGNIFICANT = 0.25
_EPS = 1e-6


def _numeric_features(df: pd.DataFrame, label_col: str | None) -> list[str]:
    numeric = df.select_dtypes(include=[np.number])
    cols = [c for c in numeric.columns if c != label_col]
    # Cap the number of features to keep baselines compact and fast.
    return [str(c) for c in cols[:40]]


def compute_baseline(df: pd.DataFrame, n_bins: int = 10) -> dict[str, Any]:
    """Capture a reusable baseline distribution snapshot for a dataframe."""
    label_col = find_label_column(df)
    features = _numeric_features(df, label_col)

    feature_bins: dict[str, Any] = {}
    for col in features:
        series = pd.to_numeric(df[col], errors="coerce").replace([np.inf, -np.inf], np.nan).dropna()
        if series.empty:
            continue
        # Quantile-based edges are robust to skew; fall back to linspace if the
        # feature is near-constant (quantiles collapse to duplicates).
        try:
            edges = np.unique(np.quantile(series, np.linspace(0, 1, n_bins + 1)))
        except Exception:
            edges = np.array([])
        if edges.size < 3:
            lo, hi = float(series.min()), float(series.max())
            if hi <= lo:
                hi = lo + 1.0
            edges = np.linspace(lo, hi, n_bins + 1)
        counts, edges = np.histogram(series, bins=edges)
        feature_bins[col] = {
            "edges": [float(e) for e in edges],
            "counts": [int(c) for c in counts],
            "mean": float(series.mean()),
            "std": float(series.std()),
        }

    label_distribution: dict[str, int] = {}
    if label_col is not None:
        vc = df[label_col].astype(str).value_counts()
        label_distribution = {str(k): int(v) for k, v in vc.items()}

    return {
        "n": int(len(df)),
        "label_column": label_col,
        "features": feature_bins,
        "label_distribution": label_distribution,
    }


def _psi(expected: np.ndarray, actual: np.ndarray) -> float:
    """Population Stability Index between two count vectors (same binning)."""
    exp = expected.astype(float)
    act = actual.astype(float)
    exp_pct = exp / max(exp.sum(), _EPS)
    act_pct = act / max(act.sum(), _EPS)
    exp_pct = np.clip(exp_pct, _EPS, None)
    act_pct = np.clip(act_pct, _EPS, None)
    return float(np.sum((act_pct - exp_pct) * np.log(act_pct / exp_pct)))


def _total_variation(a: dict[str, int], b: dict[str, int]) -> float:
    keys = set(a) | set(b)
    ta = max(sum(a.values()), 1)
    tb = max(sum(b.values()), 1)
    return 0.5 * sum(abs(a.get(k, 0) / ta - b.get(k, 0) / tb) for k in keys)


def detect_drift(
    baseline: dict[str, Any],
    candidate_df: pd.DataFrame | None = None,
    *,
    recent_accuracy: float | None = None,
    baseline_accuracy: float | None = None,
    recent_confidence: float | None = None,
) -> dict[str, Any]:
    """Compare a baseline snapshot against candidate data / live signals."""
    feature_psi: dict[str, float] = {}
    drifted_features: list[str] = []

    base_features: dict[str, Any] = baseline.get("features", {}) if baseline else {}
    if candidate_df is not None and base_features:
        for col, spec in base_features.items():
            if col not in candidate_df.columns:
                continue
            edges = np.array(spec.get("edges", []), dtype=float)
            if edges.size < 3:
                continue
            series = (
                pd.to_numeric(candidate_df[col], errors="coerce")
                .replace([np.inf, -np.inf], np.nan)
                .dropna()
            )
            if series.empty:
                continue
            actual_counts, _ = np.histogram(series, bins=edges)
            psi = _psi(np.array(spec.get("counts", [])), actual_counts)
            feature_psi[col] = round(psi, 4)
            if psi > PSI_MODERATE:
                drifted_features.append(col)

    avg_psi = round(float(np.mean(list(feature_psi.values()))), 4) if feature_psi else 0.0
    max_psi = round(float(np.max(list(feature_psi.values()))), 4) if feature_psi else 0.0

    # Label drift (total-variation distance between class mixes).
    label_drift = 0.0
    if candidate_df is not None and baseline.get("label_distribution"):
        label_col = baseline.get("label_column") or find_label_column(candidate_df)
        if label_col is not None and label_col in candidate_df.columns:
            cand_dist = {
                str(k): int(v)
                for k, v in candidate_df[label_col].astype(str).value_counts().items()
            }
            label_drift = round(_total_variation(baseline["label_distribution"], cand_dist), 4)

    # Concept drift (accuracy / confidence degradation on recent data).
    accuracy_drop = None
    if recent_accuracy is not None and baseline_accuracy is not None:
        accuracy_drop = round(float(baseline_accuracy) - float(recent_accuracy), 4)

    # --- classify ---------------------------------------------------------
    drift_types: list[str] = []
    if max_psi > PSI_SIGNIFICANT or avg_psi > PSI_MODERATE:
        drift_types.append("covariate_shift")
    if label_drift > 0.2:
        drift_types.append("label_drift")
    if (accuracy_drop is not None and accuracy_drop > 0.05) or (
        recent_confidence is not None and recent_confidence < 0.5
    ):
        drift_types.append("concept_drift")

    if max_psi > PSI_SIGNIFICANT or label_drift > 0.3 or (accuracy_drop or 0) > 0.1:
        severity = "significant"
    elif avg_psi > PSI_MODERATE or label_drift > 0.15 or drift_types:
        severity = "moderate"
    else:
        severity = "none"

    recommend = severity == "significant"

    summary = (
        f"Significant {', '.join(drift_types) or 'distribution'} drift detected — "
        "retraining recommended (pending evaluation & approval)."
        if recommend
        else (
            f"Moderate drift ({', '.join(drift_types)}) — monitor; no retraining required yet."
            if severity == "moderate"
            else "No significant drift detected."
        )
    )

    return {
        "severity": severity,
        "drift_types": drift_types,
        "recommend_retraining": recommend,
        "avg_psi": avg_psi,
        "max_psi": max_psi,
        "drifted_features": drifted_features,
        "feature_psi": feature_psi,
        "label_drift": label_drift,
        "accuracy_drop": accuracy_drop,
        "recent_confidence": recent_confidence,
        "baseline_rows": baseline.get("n") if baseline else None,
        "candidate_rows": int(len(candidate_df)) if candidate_df is not None else None,
        "summary": summary,
        "thresholds": {"psi_moderate": PSI_MODERATE, "psi_significant": PSI_SIGNIFICANT},
    }
