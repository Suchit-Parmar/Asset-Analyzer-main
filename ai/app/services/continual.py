"""Continual-learning orchestrator (Phase 12, step 4).

Wires the individual services into the safe pipeline mandated by the spec::

    New dataset → Quality check → Feature validation → Graph construction
      → Dataset versioning → Drift detection → Candidate retraining
      → Evaluation → Compare with active model → (if better) new registry version
      → **user approval** → activate only if approved.

Nothing here activates a model. Ingestion versions data and reports drift;
retraining produces a *candidate* (never the active checkpoint); comparison and
approval are separate, explicit steps driven by the user.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import pandas as pd

from app.services import drift, model_compare
from app.services.dataset_manager import dataset_manager
from app.services.registry import model_registry
from app.services.replay_buffer import replay_buffer
from app.services.review_queue import review_queue
from app.services.training import _dataset_slug, training_service


def ingest_dataframe(
    name: str,
    df: pd.DataFrame,
    source: str = "upload",
) -> dict[str, Any]:
    """Run quality → versioning → drift for freshly collected data."""
    # Capture the previous baseline *before* registering the new version so we
    # can measure drift between the old and new distributions.
    baseline_before = dataset_manager.get_baseline(name)

    result = dataset_manager.register_dataframe(name, df, source=source)

    drift_report: dict[str, Any] | None = None
    if result.get("accepted") and baseline_before:
        drift_report = drift.detect_drift(baseline_before, df)

    return {
        "dataset": result,
        "drift": drift_report,
        "next_step": (
            "retrain_recommended" if (drift_report and drift_report.get("recommend_retraining"))
            else "monitor"
        ),
    }


def analyze_drift(name: str, df: pd.DataFrame) -> dict[str, Any]:
    """Ad-hoc drift analysis of candidate data against a dataset's baseline."""
    baseline = dataset_manager.get_baseline(name)
    if not baseline:
        return {
            "available": False,
            "message": f"No baseline for '{name}'. Register a dataset version first.",
        }
    report = drift.detect_drift(baseline, df)
    return {"available": True, **report}


def retrain_candidate(
    dataset_id: str,
    architecture: str = "gat",
    hyperparameters: dict[str, Any] | None = None,
    epochs: int = 30,
    graph_strategy: str | None = None,
    graph_params: dict[str, Any] | None = None,
    mode: str = "full",
    use_replay: bool = False,
    replay_ratio: float = 0.15,
    include_review_samples: bool = False,
) -> dict[str, Any]:
    """Train a *candidate* model (never activated automatically).

    ``mode`` selects the retraining strategy:
      * ``full``        – train from scratch,
      * ``incremental`` / ``finetune`` – warm-start from the dataset's checkpoint,
      * ``transfer``    – warm-start from the currently active model,
      * ``resume``      – warm-start from the dataset's checkpoint and continue.
    """
    base_slug = _dataset_slug(dataset_id)
    stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    candidate_slug = f"{base_slug}__candidate_{stamp}"

    init_from: str | None = None
    if mode in ("incremental", "finetune", "resume"):
        init_from = base_slug
    elif mode == "transfer":
        init_from = "tgnn_model"  # the currently active model

    hp = dict(hyperparameters or {})
    if mode in ("incremental", "finetune"):
        hp["learning_rate"] = float(hp.get("learning_rate", 0.0005)) * 0.25
        epochs = min(epochs, 25)

    extra_rows: list[dict[str, Any]] = []
    if include_review_samples:
        for sample in review_queue.approved_samples():
            label = sample.get("true_label") or sample.get("predicted_attack_type")
            features = sample.get("features") or {}
            if label and isinstance(features, dict) and features:
                row = dict(features)
                row["Label"] = label
                row["attack_type"] = label
                extra_rows.append(row)
                replay_buffer.add_from_review_sample(sample)

    if use_replay:
        max_rows = int(hp.get("max_rows", 20000))
        n_replay = max(1, int(max_rows * max(0.0, min(replay_ratio, 0.5))))
        extra_rows.extend(replay_buffer.sample(n_replay))

    run = training_service.start_training(
        run_id=str(uuid.uuid4()),
        dataset_id=dataset_id,
        architecture=architecture,
        hyperparameters=hp,
        epochs=epochs,
        graph_strategy=graph_strategy,
        graph_params=graph_params,
        activate=False,           # <-- safety: candidate only
        model_slug=candidate_slug,
        init_from=init_from,
        mode=mode,
        extra_rows=extra_rows or None,
    )
    return {
        "run_id": run.get("run_id"),
        "candidate_id": candidate_slug,
        "mode": mode,
        "init_from": init_from,
        "activate": False,
        "replay_rows": len(extra_rows),
        "replay_stats": replay_buffer.stats(),
        "message": "Candidate training started. Compare and approve before activation.",
    }


def compare_with_active(candidate_id: str) -> dict[str, Any]:
    """Compare the active model against a candidate using registry metadata."""
    candidate_meta = model_registry.get_metadata(candidate_id)
    candidate_metrics = _full_metrics(candidate_id)

    active_dataset, active_trained_at = model_registry._active_fingerprint()
    active_metrics, active_size, active_id = _active_full_metrics(active_dataset, active_trained_at)

    report = model_compare.compare(
        active_metrics,
        candidate_metrics,
        active_size=active_size,
        candidate_size=candidate_meta.get("size_bytes"),
    )
    return {
        "candidate_id": candidate_id,
        "active_id": active_id,
        "active": {"dataset_id": active_dataset, "trained_at": active_trained_at},
        "comparison": report,
    }


def approve_candidate(candidate_id: str, approved_by: str | None = None) -> dict[str, Any]:
    """Promote a candidate to the active model (explicit user approval)."""
    from app.services.experiments import approval_store

    comparison = None
    legacy_warning: str | None = None
    try:
        comparison = compare_with_active(candidate_id).get("comparison")
        rec = (comparison or {}).get("recommendation")
        if rec == "keep_active":
            legacy_warning = (
                "Comparison recommends keeping the active model; approval still requires explicit operator action."
            )
    except Exception:
        comparison = None

    backup_info = model_registry.rollback_info()
    result = model_registry.activate(candidate_id)
    approval_store.record({
        "candidate_id": candidate_id,
        "approved_by": approved_by,
        "comparison_recommendation": (comparison or {}).get("recommendation"),
        "active_dataset": result.get("model_info", {}).get("dataset_id"),
        "metrics_delta": (comparison or {}).get("delta"),
        "previous_active": result.get("previous_active") or backup_info,
    })
    out = {
        "approved": candidate_id,
        "activated": True,
        **result,
    }
    if legacy_warning:
        out["warning"] = legacy_warning
    return out


def rollback_active() -> dict[str, Any]:
    """Restore the previous active checkpoint (one-step rollback)."""
    info = model_registry.rollback()
    from app.services.experiments import approval_store

    approval_store.record({
        "candidate_id": info.get("previous_model_id") or "previous_active",
        "approved_by": "rollback",
        "comparison_recommendation": "rollback",
        "active_dataset": info.get("model_info", {}).get("dataset_id"),
        "metrics_delta": {"action": "rollback"},
        "previous_active": {"restored_from": info.get("restored_from")},
    })
    return info


def replay_stats() -> dict[str, Any]:
    return replay_buffer.stats()


# -- helpers ---------------------------------------------------------------

def _full_metrics(model_id: str) -> dict[str, Any]:
    """Load the full metrics dict from a checkpoint (registry sidecars are compact)."""
    import torch

    try:
        path = model_registry.checkpoint_file(model_id)
        ckpt = torch.load(path, map_location="cpu", weights_only=False)
        return ckpt.get("metrics", {}) or {}
    except Exception:
        return {}


def _active_full_metrics(
    active_dataset: str | None, active_trained_at: str | None
) -> tuple[dict[str, Any], int | None, str | None]:
    import torch

    active_path = model_registry.model_dir / "tgnn_model.pt"
    if not active_path.exists():
        return {}, None, None
    try:
        ckpt = torch.load(active_path, map_location="cpu", weights_only=False)
        size = active_path.stat().st_size
        return ckpt.get("metrics", {}) or {}, size, active_dataset
    except Exception:
        return {}, None, active_dataset
