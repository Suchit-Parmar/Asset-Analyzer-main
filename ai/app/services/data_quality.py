"""Data quality analysis (Phase 12, step 2).

Before any new dataset is versioned or used for retraining it is screened here.
The analyzer produces a structured, human-readable *quality report* and a hard
``passed`` verdict. Invalid datasets are rejected so the continual-learning loop
cannot be poisoned by duplicate, corrupted or mislabelled traffic.

Checks performed:

  * Duplicate flows        – fully identical rows.
  * Missing values         – NaN/empty cells (total + worst columns).
  * Corrupted rows         – all-NaN rows and non-finite (inf) numeric values.
  * Unknown attack labels  – labels that do not map to the known taxonomy.
  * Feature mismatch       – expected feature columns that are absent.
  * Class distribution     – per-class counts (used later for drift/balance).

The verdict is deliberately conservative but not brittle: empty datasets and
datasets that are almost entirely duplicates/missing are rejected; everything
else passes with warnings so a researcher stays in control.
"""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

from app.models.tgnn import ATTACK_TYPES

# Labels we treat as benign regardless of dataset casing/spelling.
_BENIGN_ALIASES = {"0", "normal", "benign", "background", "none", ""}

# Common column names that hold the attack label across supported datasets.
_LABEL_CANDIDATES = ("attack_type", "attack_cat", "Label", "label", "Attack", "category")

_KNOWN_LABELS = {t.lower() for t in ATTACK_TYPES} | _BENIGN_ALIASES


def find_label_column(df: pd.DataFrame) -> str | None:
    """Return the most likely attack-label column, or ``None``."""
    for col in _LABEL_CANDIDATES:
        if col in df.columns:
            return col
    # Fall back to any column literally named like a label.
    for col in df.columns:
        if str(col).strip().lower() in ("label", "attack", "attack_type", "attack_cat"):
            return col
    return None


def _is_known_label(value: Any) -> bool:
    text = str(value).strip().lower()
    if text in _KNOWN_LABELS:
        return True
    # Fuzzy bucket for dataset-specific spellings (e.g. "DoS Hulk", "PortScan").
    for token in ("dos", "ddos", "scan", "probe", "bot", "brute", "patator",
                  "web", "infiltrat", "heartbleed", "exploit", "fuzz", "worm",
                  "shellcode", "backdoor", "reconnaissance", "generic", "analysis"):
        if token in text:
            return True
    return False


def analyze(
    df: pd.DataFrame,
    expected_features: list[str] | None = None,
) -> dict[str, Any]:
    """Analyze a dataframe and return a quality report with a ``passed`` verdict."""
    n_rows = int(len(df))
    n_cols = int(df.shape[1]) if n_rows else 0
    issues: list[str] = []
    warnings: list[str] = []

    if n_rows == 0:
        return {
            "passed": False,
            "score": 0.0,
            "rows": 0,
            "columns": 0,
            "issues": ["Dataset is empty (0 rows)."],
            "warnings": [],
            "duplicates": 0,
            "missing_values": 0,
            "corrupted_rows": 0,
            "unknown_labels": {},
            "feature_mismatch": [],
            "class_distribution": {},
        }

    # --- duplicates -------------------------------------------------------
    duplicates = int(df.duplicated().sum())
    dup_ratio = duplicates / n_rows

    # --- missing values ---------------------------------------------------
    na_matrix = df.isna()
    missing_total = int(na_matrix.to_numpy().sum())
    missing_ratio = missing_total / float(n_rows * max(n_cols, 1))
    worst_missing = (
        na_matrix.sum().sort_values(ascending=False).head(5)
    )
    missing_by_column = {
        str(col): int(cnt) for col, cnt in worst_missing.items() if cnt > 0
    }

    # --- corrupted rows (all-NaN rows + non-finite numeric cells) ---------
    all_nan_rows = int(na_matrix.all(axis=1).sum())
    numeric = df.select_dtypes(include=[np.number])
    inf_cells = int(np.isinf(numeric.to_numpy()).sum()) if not numeric.empty else 0
    corrupted_rows = all_nan_rows

    # --- labels -----------------------------------------------------------
    label_col = find_label_column(df)
    unknown_labels: dict[str, int] = {}
    class_distribution: dict[str, int] = {}
    if label_col is not None:
        counts = df[label_col].astype(str).value_counts()
        class_distribution = {str(k): int(v) for k, v in counts.items()}
        for label, cnt in counts.items():
            if not _is_known_label(label):
                unknown_labels[str(label)] = int(cnt)
    else:
        warnings.append("No attack-label column found; treating dataset as unlabelled.")

    # --- feature mismatch -------------------------------------------------
    feature_mismatch: list[str] = []
    if expected_features:
        present = {str(c).strip().lower() for c in df.columns}
        for feat in expected_features:
            if str(feat).strip().lower() not in present:
                feature_mismatch.append(str(feat))

    # --- assemble verdict -------------------------------------------------
    if dup_ratio > 0.9:
        issues.append(f"{duplicates} duplicate rows ({dup_ratio:.0%}) — dataset is almost entirely duplicates.")
    elif duplicates > 0:
        warnings.append(f"{duplicates} duplicate rows ({dup_ratio:.1%}).")

    if missing_ratio > 0.5:
        issues.append(f"{missing_total} missing cells ({missing_ratio:.0%}) — too much missing data.")
    elif missing_total > 0:
        warnings.append(f"{missing_total} missing cells ({missing_ratio:.2%}).")

    if all_nan_rows > 0:
        warnings.append(f"{all_nan_rows} fully empty (corrupted) rows.")
    if inf_cells > 0:
        warnings.append(f"{inf_cells} non-finite numeric values (inf).")

    if unknown_labels:
        total_unknown = sum(unknown_labels.values())
        if total_unknown / n_rows > 0.5:
            issues.append(f"{total_unknown} rows have unknown attack labels ({len(unknown_labels)} distinct).")
        else:
            warnings.append(f"{len(unknown_labels)} unknown attack label(s) detected — review before training.")

    if feature_mismatch:
        warnings.append(f"{len(feature_mismatch)} expected feature(s) missing: {feature_mismatch[:6]}")

    if label_col is not None and len(class_distribution) < 2:
        warnings.append("Only a single class present — unsuitable for supervised evaluation on its own.")

    # Quality score: 1.0 minus penalties for duplicates / missing / unknown.
    unknown_ratio = (sum(unknown_labels.values()) / n_rows) if unknown_labels else 0.0
    score = max(0.0, 1.0 - (dup_ratio * 0.5 + missing_ratio * 0.5 + unknown_ratio * 0.5))

    return {
        "passed": len(issues) == 0,
        "score": round(float(score), 4),
        "rows": n_rows,
        "columns": n_cols,
        "label_column": label_col,
        "duplicates": duplicates,
        "duplicate_ratio": round(dup_ratio, 4),
        "missing_values": missing_total,
        "missing_ratio": round(missing_ratio, 4),
        "missing_by_column": missing_by_column,
        "corrupted_rows": corrupted_rows,
        "non_finite_values": inf_cells,
        "unknown_labels": unknown_labels,
        "feature_mismatch": feature_mismatch,
        "class_distribution": class_distribution,
        "issues": issues,
        "warnings": warnings,
    }
