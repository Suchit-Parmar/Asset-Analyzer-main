"""TGNN training service (PyTorch Geometric)."""

from __future__ import annotations

import os
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.cuda.amp import GradScaler, autocast
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.preprocessing import label_binarize

from app.data.loaders import load_dataset
from app.graph.builder import NODE_FEATURE_DIM, TemporalGraphBuilder
from app.graph.strategies import (
    DEFAULT_STRATEGY,
    GraphConfig,
    build_snapshots,
    graph_structure_stats,
)
from app.models.tgnn import ATTACK_STAGES, ATTACK_TYPES, TGNNModel
from app.services.feature_selection import metadata_payload


def _resolve_model_dir() -> Path:
    env = os.environ.get("MODEL_DIR")
    if env:
        return Path(env).expanduser().resolve()
    # Default: <repo>/ai/models
    return Path(__file__).resolve().parents[2] / "models"


MODEL_DIR = _resolve_model_dir()

# Canonical dataset slugs → checkpoint filename stems. Keeps per-dataset
# checkpoints stable and works for UNSW, CICIDS2017, and future datasets.
_DATASET_SLUG_ALIASES = {
    "cicids2017": "cicids2017",
    "cicids": "cicids2017",
    "cic_ids_2017": "cicids2017",
    "unsw_nb15": "unsw_nb15",
    "unsw": "unsw_nb15",
    "unsw-nb15": "unsw_nb15",
    "cse_cic_ids2018": "cse_cic_ids2018",
    "cicids2018": "cse_cic_ids2018",
    "cse-cic-ids2018": "cse_cic_ids2018",
}


def _dataset_slug(dataset_id: str) -> str:
    """Filesystem-safe canonical slug for a dataset checkpoint filename."""
    key = (dataset_id or "").strip().lower().replace(" ", "_")
    if key in _DATASET_SLUG_ALIASES:
        return _DATASET_SLUG_ALIASES[key]
    # Fall back to a sanitized version of whatever was requested.
    safe = "".join(ch if ch.isalnum() or ch in ("_", "-") else "_" for ch in key)
    return safe or "model"

STAGE_FROM_ATTACK = {
    "Normal": 0,
    "normal": 0,
    "Reconnaissance": 1,
    "Probe": 2,
    "Fuzzers": 2,
    "Generic": 3,
    "Exploits": 3,
    "R2L": 3,
    "Brute Force": 3,
    "Web Attack": 3,
    "U2R": 4,
    "Backdoor": 4,
    "Heartbleed": 4,
    "DoS": 7,
    "DDoS": 7,
    "Analysis": 1,
    "Shellcode": 5,
    "Worms": 5,
    "Infiltration": 5,
    "Botnet": 5,
}

ATTACK_TO_IDX = {name: i for i, name in enumerate(ATTACK_TYPES)}


class TrainingService:
    def __init__(self):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.active_runs: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def start_training(
        self,
        run_id: str | None = None,
        dataset_id: str = "cicids2017",
        architecture: str = "gat",
        hyperparameters: dict | None = None,
        epochs: int = 50,
        graph_strategy: str | None = None,
        graph_params: dict | None = None,
        feature_set: dict | None = None,
        activate: bool = True,
        model_slug: str | None = None,
        init_from: str | None = None,
        mode: str = "full",
        extra_rows: list[dict] | None = None,
    ) -> dict[str, Any]:
        run_id = run_id or str(uuid.uuid4())
        hp = hyperparameters or {}
        hidden_dim = int(hp.get("hidden_dim", 64))
        lr = float(hp.get("learning_rate", 0.0005))
        batch_size = int(hp.get("batch_size", 32))
        max_rows = int(hp.get("max_rows", 20000))
        window_seconds = int(hp.get("window_seconds", 30))
        early_stop_patience = int(hp.get("early_stop_patience", 8))
        grad_clip = float(hp.get("grad_clip", 5.0))
        use_amp = bool(hp.get("use_amp", torch.cuda.is_available()))

        # Graph strategy may arrive as top-level args or nested in hyperparameters
        # (backward compatible with older callers that only send hyperparameters).
        strategy = graph_strategy or hp.get("graph_strategy") or DEFAULT_STRATEGY
        params = dict(graph_params or hp.get("graph_params") or {})
        params.setdefault("window_size", window_seconds)
        if feature_set is not None:
            params["feature_set"] = feature_set
        elif hp.get("feature_set") is not None:
            params["feature_set"] = hp.get("feature_set")
        graph_config = GraphConfig.from_dict(strategy, params)

        with self._lock:
            self.active_runs[run_id] = {
                "run_id": run_id,
                "status": "running",
                "dataset_id": dataset_id,
                "architecture": architecture,
                "epochs": epochs,
                "current_epoch": 0,
                "train_loss": None,
                "val_loss": None,
                "train_accuracy": None,
                "val_accuracy": None,
                "metrics": {},
                "graph_strategy": graph_config.strategy,
                "graph_params": graph_config.to_metadata(),
                "feature_set": graph_config.feature_set,
                "mode": mode,
                "activate": activate,
                "model_slug": model_slug,
                "init_from": init_from,
                "extra_rows_count": len(extra_rows or []),
                "device": str(self.device),
                "use_amp": use_amp,
                "learning_rate": lr,
                "early_stop_patience": early_stop_patience,
                "grad_clip": grad_clip,
                "eta_seconds": None,
                "logs": [],
                "gpu_utilization": self._gpu_util(),
                "started_at": datetime.utcnow().isoformat(),
                "history": [],
            }

        thread = threading.Thread(
            target=self._train_worker,
            args=(
                run_id,
                dataset_id,
                architecture,
                epochs,
                hidden_dim,
                lr,
                batch_size,
                max_rows,
                window_seconds,
                graph_config,
            ),
            kwargs={
                "activate": activate,
                "model_slug": model_slug,
                "init_from": init_from,
                "mode": mode,
                "extra_rows": extra_rows,
            },
            daemon=True,
        )
        thread.start()
        return self.active_runs[run_id]

    def train_sync(
        self,
        dataset_id: str = "cicids2017",
        architecture: str = "gat",
        epochs: int = 10,
        hidden_dim: int = 64,
        learning_rate: float = 0.001,
        max_rows: int = 10000,
        window_seconds: int = 30,
        run_id: str | None = None,
        graph_strategy: str | None = None,
        graph_params: dict | None = None,
        activate: bool = True,
        model_slug: str | None = None,
        init_from: str | None = None,
        mode: str = "full",
    ) -> dict[str, Any]:
        """Run training on the calling thread (used for Phase 2 verification)."""
        run_id = run_id or str(uuid.uuid4())
        params = dict(graph_params or {})
        params.setdefault("window_size", window_seconds)
        graph_config = GraphConfig.from_dict(graph_strategy or DEFAULT_STRATEGY, params)
        with self._lock:
            self.active_runs[run_id] = {
                "run_id": run_id,
                "status": "running",
                "dataset_id": dataset_id,
                "architecture": architecture,
                "epochs": epochs,
                "current_epoch": 0,
                "train_loss": None,
                "val_loss": None,
                "train_accuracy": None,
                "val_accuracy": None,
                "metrics": {},
                "gpu_utilization": self._gpu_util(),
                "started_at": datetime.utcnow().isoformat(),
                "history": [],
            }

        self._train_worker(
            run_id,
            dataset_id,
            architecture,
            epochs,
            hidden_dim,
            learning_rate,
            32,
            max_rows,
            window_seconds,
            graph_config,
            activate=activate,
            model_slug=model_slug,
            init_from=init_from,
            mode=mode,
        )
        return self.active_runs[run_id]

    def get_status(self, run_id: str) -> dict[str, Any] | None:
        return self.active_runs.get(run_id)

    def _train_worker(
        self,
        run_id: str,
        dataset_id: str,
        architecture: str,
        epochs: int,
        hidden_dim: int,
        lr: float,
        batch_size: int,
        max_rows: int,
        window_seconds: int,
        graph_config: GraphConfig | None = None,
        activate: bool = True,
        model_slug: str | None = None,
        init_from: str | None = None,
        mode: str = "full",
        extra_rows: list[dict] | None = None,
    ) -> None:
        try:
            graph_config = graph_config or GraphConfig.from_dict(
                DEFAULT_STRATEGY, {"window_size": window_seconds}
            )
            print(f"[train] Device: {self.device}")
            print(f"[train] Dataset: {dataset_id} | architecture={architecture} | epochs={epochs}")
            print(f"[train] Graph strategy: {graph_config.strategy} | params={graph_config.to_metadata()}")
            if graph_config.feature_set:
                print(f"[train] Feature set: {graph_config.feature_set}")
            print(f"[train] Loading data (max_rows={max_rows})...")
            df = load_dataset(dataset_id, max_rows=max_rows)
            if extra_rows:
                import pandas as pd

                replay_df = pd.DataFrame(extra_rows)
                if not replay_df.empty:
                    df = pd.concat([df, replay_df], ignore_index=True)
                    print(f"[train] Merged {len(replay_df)} replay/review rows (total={len(df)})")

            print(f"[train] Building '{graph_config.strategy}' graphs...")
            snapshots = build_snapshots(df, graph_config)
            if not snapshots:
                builder = TemporalGraphBuilder(window_seconds=window_seconds)
                snapshots = [builder.build_single_snapshot(df.head(min(1000, len(df))))]

            labeled = [s for s in snapshots if s.get("node_count", 0) > 0]
            if not labeled:
                raise RuntimeError("No non-empty graph snapshots were built from the dataset")

            # Free the raw dataframe now that graphs are built (Module D memory
            # hygiene for large 250K-1M row datasets).
            del df
            snapshots = labeled
            import gc

            gc.collect()

            graph_stats = graph_structure_stats(labeled)
            print(
                f"[train] Snapshots: {len(labeled)} | "
                f"avg nodes={graph_stats['avg_nodes']:.1f} | "
                f"avg edges={graph_stats['avg_edges']:.1f} | "
                f"density={graph_stats['avg_density']:.4f} | "
                f"avg degree={graph_stats['avg_degree']:.2f}"
            )

            # Representative split. The source CSVs are label-ordered, so a plain
            # chronological tail split makes the validation set a single attack
            # class (e.g. all DoS) — that collapses every validation metric to a
            # meaningless 0 or 1. Interleaving every 5th snapshot into validation
            # is deterministic and lets both sets span all classes/time windows.
            # Deterministic 70/15/15 train / validation / test split. Interleaving
            # by index (rather than a chronological tail) keeps every class and
            # time window represented in all three splits — important because the
            # snapshot count is small and time-ordered. The test split is held out
            # entirely from training/model-selection for an unbiased final score.
            if len(labeled) < 7:
                train_snaps = labeled
                val_snaps = labeled[-1:]
                test_snaps = labeled[-1:]
            else:
                test_snaps = [s for i, s in enumerate(labeled) if i % 7 == 0]
                val_snaps = [s for i, s in enumerate(labeled) if i % 7 == 1]
                train_snaps = [s for i, s in enumerate(labeled) if i % 7 not in (0, 1)]

            def _class_spread(snaps: list[dict[str, Any]]) -> dict[str, int]:
                counts: dict[str, int] = {}
                for s in snaps:
                    name, _ = self._snapshot_labels(s)
                    key = ATTACK_TYPES[name] if isinstance(name, int) else str(name)
                    counts[key] = counts.get(key, 0) + 1
                return counts

            print(
                f"[train] Split 70/15/15 -> train={len(train_snaps)} "
                f"val={len(val_snaps)} test={len(test_snaps)}"
            )
            print(f"[train] Val class spread:  {_class_spread(val_snaps)}")
            print(f"[train] Test class spread: {_class_spread(test_snaps)}")

            model = TGNNModel(
                node_features=NODE_FEATURE_DIM,
                hidden_dim=hidden_dim,
                architecture=architecture,
            ).to(self.device)

            # Smart retraining (Phase 12): warm-start from an existing checkpoint
            # for incremental fine-tuning / transfer learning / resume. Loaded
            # with strict=False so mismatched buffers fall back to defaults.
            if init_from:
                try:
                    src = MODEL_DIR / f"{_dataset_slug(init_from)}.pt"
                    if not src.exists():
                        src = MODEL_DIR / f"{init_from}.pt"
                    if not src.exists() and init_from.endswith(".pt"):
                        src = MODEL_DIR / init_from
                    if src.exists():
                        prior = torch.load(src, map_location=self.device, weights_only=False)
                        model.load_state_dict(prior.get("model_state", {}), strict=False)
                        print(f"[train] Warm-start ({mode}) from {src}")
                    else:
                        print(f"[train] Warm-start source not found for '{init_from}'; training from scratch")
                except Exception as warm_err:  # noqa: BLE001
                    print(f"[train] Warm-start skipped: {warm_err}")

            # Standardize node features using training-set statistics so no single
            # feature (e.g. log-bytes ~15 vs conn_ratio ~0.02) dominates learning.
            feat_mean, feat_std = self._feature_stats(train_snaps)
            model.feat_mean.copy_(feat_mean.to(self.device))
            model.feat_std.copy_(feat_std.to(self.device))

            # Class weights counter the heavy imbalance (majority class collapse).
            class_weights = self._class_weights(train_snaps).to(self.device)
            print(f"[train] Class weights: {[round(float(w), 3) for w in class_weights]}")

            optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-4)
            scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
                optimizer, mode="min", factor=0.5, patience=3, min_lr=1e-5
            )
            attack_criterion = nn.CrossEntropyLoss(weight=class_weights)
            stage_criterion = nn.CrossEntropyLoss()

            history: list[dict[str, Any]] = []
            best_score = -1.0
            best_metrics: dict[str, Any] | None = None
            best_state: dict[str, Any] | None = None
            epochs_without_improvement = 0
            scaler = GradScaler(enabled=use_amp and self.device.type == "cuda")
            runs_dir = MODEL_DIR / "runs"
            runs_dir.mkdir(parents=True, exist_ok=True)

            train_start = time.perf_counter()
            stopped_early = False
            for epoch in range(epochs):
                train_stats = self._run_epoch(
                    model,
                    train_snaps,
                    optimizer,
                    attack_criterion,
                    stage_criterion,
                    train=True,
                    scaler=scaler,
                    use_amp=use_amp and self.device.type == "cuda",
                    grad_clip=grad_clip,
                )
                val_stats = self._run_epoch(
                    model,
                    val_snaps,
                    optimizer,
                    attack_criterion,
                    stage_criterion,
                    train=False,
                    use_amp=use_amp and self.device.type == "cuda",
                )

                scheduler.step(val_stats["loss"])
                current_lr = float(optimizer.param_groups[0]["lr"])

                epoch_metrics = {
                    "epoch": epoch + 1,
                    "train_loss": round(train_stats["loss"], 4),
                    "val_loss": round(val_stats["loss"], 4),
                    "train_accuracy": round(train_stats["accuracy"], 4),
                    "val_accuracy": round(val_stats["accuracy"], 4),
                    "precision": round(val_stats["precision"], 4),
                    "recall": round(val_stats["recall"], 4),
                    "f1": round(val_stats["f1"], 4),
                    "learning_rate": round(current_lr, 6),
                }
                history.append(epoch_metrics)

                # Track the best epoch (by f1, tie-broken by val accuracy) and
                # snapshot its weights. The saved checkpoint is the best model,
                # so reported metrics and saved weights stay consistent and a
                # single degenerate final epoch can't zero out the checkpoint.
                epoch_score = epoch_metrics["f1"] + epoch_metrics["val_accuracy"] * 1e-3
                if epoch_score > best_score:
                    best_score = epoch_score
                    best_metrics = epoch_metrics
                    best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
                    epochs_without_improvement = 0
                    interim_path = runs_dir / f"{run_id}_best.pt"
                    torch.save(
                        {
                            "model_state": best_state,
                            "epoch": epoch + 1,
                            "metrics": epoch_metrics,
                            "run_id": run_id,
                            "dataset_id": dataset_id,
                        },
                        interim_path,
                    )
                else:
                    epochs_without_improvement += 1

                elapsed = time.perf_counter() - train_start
                avg_epoch_time = elapsed / (epoch + 1)
                eta_seconds = round(avg_epoch_time * max(epochs - epoch - 1, 0), 1)

                log_line = (
                    f"Epoch {epoch + 1}/{epochs} | loss={epoch_metrics['train_loss']:.4f} "
                    f"val_loss={epoch_metrics['val_loss']:.4f} | "
                    f"acc={epoch_metrics['train_accuracy']:.4f} "
                    f"val_acc={epoch_metrics['val_accuracy']:.4f} | "
                    f"f1={epoch_metrics['f1']:.4f} | lr={current_lr:.6f} | "
                    f"eta={eta_seconds:.0f}s"
                )
                print(f"[train] {log_line}")

                with self._lock:
                    run = self.active_runs[run_id]
                    run["current_epoch"] = epoch + 1
                    run["train_loss"] = epoch_metrics["train_loss"]
                    run["val_loss"] = epoch_metrics["val_loss"]
                    run["train_accuracy"] = epoch_metrics["train_accuracy"]
                    run["val_accuracy"] = epoch_metrics["val_accuracy"]
                    run["learning_rate"] = current_lr
                    run["gpu_utilization"] = self._gpu_util()
                    run["eta_seconds"] = eta_seconds
                    run["history"].append(epoch_metrics)
                    run["logs"] = (run.get("logs") or [])[-199:] + [
                        {"time": datetime.utcnow().isoformat(), "text": log_line}
                    ]
                    run["interim_checkpoint"] = str(runs_dir / f"{run_id}_best.pt")

                if epochs_without_improvement >= early_stop_patience:
                    print(
                        f"[train] Early stopping at epoch {epoch + 1} "
                        f"(no improvement for {early_stop_patience} epochs)"
                    )
                    stopped_early = True
                    break

            # Restore the best epoch's weights so the saved model matches the
            # reported metrics (instead of blindly keeping the last epoch).
            selected = best_metrics or (history[-1] if history else {})
            if best_state is not None:
                model.load_state_dict(best_state)

            training_time_sec = round(time.perf_counter() - train_start, 2)

            # Research-grade evaluation of the best model on the held-out splits:
            # macro/weighted P-R-F1, ROC-AUC (OvR), confusion matrix and per-class
            # breakdown. The test split never influenced training or selection.
            val_eval = self._evaluate_split(model, val_snaps)
            inf_start = time.perf_counter()
            test_eval = self._evaluate_split(model, test_snaps)
            inference_time_ms = round(
                (time.perf_counter() - inf_start) / max(len(test_snaps), 1) * 1000.0, 3
            )

            final_metrics = {
                # Backward-compatible headline keys (validation, best epoch).
                "accuracy": selected.get("val_accuracy", 0.0),
                "precision": selected.get("precision", 0.0),
                "recall": selected.get("recall", 0.0),
                "f1": selected.get("f1", 0.0),
                "train_loss": selected.get("train_loss", 0.0),
                "val_loss": selected.get("val_loss", 0.0),
                "best_epoch": selected.get("epoch"),
                "epochs": len(history),
                "epochs_requested": epochs,
                "stopped_early": stopped_early,
                "early_stop_patience": early_stop_patience,
                "use_amp": use_amp and self.device.type == "cuda",
                "device": str(self.device),
                "grad_clip": grad_clip,
                "dataset_id": dataset_id,
                "architecture": architecture,
                "num_snapshots": len(labeled),
                "history": history,
                # New research metrics (headline = held-out test split).
                "split": {
                    "ratio": "70/15/15",
                    "train": len(train_snaps),
                    "val": len(val_snaps),
                    "test": len(test_snaps),
                },
                "macro_f1": test_eval.get("macro_f1", 0.0),
                "weighted_f1": test_eval.get("weighted_f1", 0.0),
                "roc_auc": test_eval.get("roc_auc"),
                "confusion_matrix": test_eval.get("confusion_matrix"),
                "class_labels": list(ATTACK_TYPES),
                "per_class": test_eval.get("per_class", {}),
                "test": {
                    "accuracy": test_eval.get("accuracy", 0.0),
                    "precision": test_eval.get("weighted_precision", 0.0),
                    "recall": test_eval.get("weighted_recall", 0.0),
                    "f1": test_eval.get("weighted_f1", 0.0),
                    "macro_precision": test_eval.get("macro_precision", 0.0),
                    "macro_recall": test_eval.get("macro_recall", 0.0),
                    "macro_f1": test_eval.get("macro_f1", 0.0),
                    "roc_auc": test_eval.get("roc_auc"),
                },
                "validation": {
                    "accuracy": val_eval.get("accuracy", 0.0),
                    "f1": val_eval.get("weighted_f1", 0.0),
                    "macro_f1": val_eval.get("macro_f1", 0.0),
                    "roc_auc": val_eval.get("roc_auc"),
                },
                # Graph strategy provenance + structure/timing (Module C).
                "graph_strategy": graph_config.strategy,
                "graph_params": graph_config.to_metadata(),
                "graph_stats": graph_stats,
                "feature_set": metadata_payload(
                    graph_config.feature_set,
                    strategy=graph_config.strategy,
                ),
                "roc_curves": test_eval.get("roc_curves") or {},
                "pr_curves": test_eval.get("pr_curves") or {},
                "class_distribution": test_eval.get("class_distribution") or [],
                "training_time_sec": training_time_sec,
                "inference_time_ms": inference_time_ms,
                "mode": mode,
                "init_from": init_from,
            }

            active_path = MODEL_DIR / "tgnn_model.pt"
            if active_path.exists():
                try:
                    from app.services.model_compare import compare

                    prior = torch.load(active_path, map_location="cpu", weights_only=False)
                    prior_metrics = prior.get("metrics") or {}
                    comparison = compare(prior_metrics, final_metrics)
                    final_metrics["model_comparison"] = comparison
                    print(
                        f"[train] Model comparison vs active: "
                        f"recommendation={comparison.get('recommendation')} | "
                        f"delta_f1={comparison.get('delta', {}).get('f1')}"
                    )
                except Exception as cmp_err:  # noqa: BLE001
                    print(f"[train] Model comparison skipped: {cmp_err}")

            print("[train] ===== Final metrics (best model) =====")
            print(f"[train] best_epoch     = {final_metrics['best_epoch']}")
            print(f"[train] train_loss     = {final_metrics['train_loss']}")
            print(f"[train] val_loss       = {final_metrics['val_loss']}")
            print(f"[train] val_accuracy   = {final_metrics['accuracy']}")
            print(f"[train] --- held-out TEST split ---")
            print(f"[train] test_accuracy  = {test_eval.get('accuracy')}")
            print(f"[train] test_precision = {test_eval.get('weighted_precision')} (weighted)")
            print(f"[train] test_recall    = {test_eval.get('weighted_recall')} (weighted)")
            print(f"[train] test_f1        = {test_eval.get('weighted_f1')} (weighted)")
            print(f"[train] test_macro_f1  = {test_eval.get('macro_f1')}")
            print(f"[train] test_roc_auc   = {test_eval.get('roc_auc')}")
            print(f"[train] per_class      = {test_eval.get('per_class')}")
            print(f"[train] graph_strategy = {graph_config.strategy} | params={graph_config.to_metadata()}")
            print(f"[train] training_time  = {training_time_sec}s | inference={inference_time_ms}ms/snapshot")

            MODEL_DIR.mkdir(parents=True, exist_ok=True)
            checkpoint = {
                "model_state": model.state_dict(),
                "architecture": architecture,
                "hidden_dim": hidden_dim,
                "node_features": NODE_FEATURE_DIM,
                "attack_types": ATTACK_TYPES,
                "attack_stages": ATTACK_STAGES,
                "metrics": final_metrics,
                "dataset_id": dataset_id,
                "graph_strategy": graph_config.strategy,
                "graph_params": graph_config.to_metadata(),
                "feature_set": final_metrics["feature_set"],
                "trained_at": datetime.utcnow().isoformat(),
            }

            # Persist a checkpoint. Normally this is the per-dataset checkpoint
            # (e.g. cicids2017.pt). Phase 12 continual learning can request a
            # distinct `model_slug` (a *candidate*) and `activate=False` so the
            # active model the inference service loads is NEVER replaced without
            # explicit user approval.
            slug = model_slug or _dataset_slug(dataset_id)
            dataset_path = MODEL_DIR / f"{slug}.pt"
            active_path = MODEL_DIR / "tgnn_model.pt"
            torch.save(checkpoint, dataset_path)
            model_path = dataset_path
            if activate:
                torch.save(checkpoint, active_path)
                model_path = active_path
                print(f"[train] Checkpoint saved: {dataset_path} (active: {active_path})")
            else:
                print(f"[train] Candidate checkpoint saved: {dataset_path} (active model unchanged)")

            # Phase 2: write a registry metadata sidecar so the model registry can
            # list this checkpoint without re-reading the full .pt file.
            try:
                from app.services.registry import model_registry

                model_registry.write_sidecar(slug, checkpoint)
            except Exception as reg_err:  # noqa: BLE001
                print(f"[train] Registry sidecar skipped: {reg_err}")

            # Phase 12: record the run in the experiment tracker (audit trail).
            try:
                from app.services.experiments import experiment_store

                experiment_store.record({
                    "run_id": run_id,
                    "dataset_id": dataset_id,
                    "architecture": architecture,
                    "mode": mode,
                    "init_from": init_from,
                    "model_slug": slug,
                    "activated": bool(activate),
                    "epochs": epochs,
                    "graph_strategy": graph_config.strategy,
                    "graph_params": graph_config.to_metadata(),
                    "hyperparameters": {
                        "hidden_dim": hidden_dim,
                        "learning_rate": lr,
                        "batch_size": batch_size,
                        "max_rows": max_rows,
                        "window_seconds": window_seconds,
                    },
                    "metrics": final_metrics,
                    "training_time_sec": training_time_sec,
                    "checkpoint": str(dataset_path),
                })
            except Exception as exp_err:  # noqa: BLE001
                print(f"[train] Experiment record skipped: {exp_err}")

            if activate:
                try:
                    from app.services.inference import inference_service

                    inference_service._load_model()
                except Exception as reload_err:
                    print(f"[train] Inference reload skipped: {reload_err}")

            with self._lock:
                self.active_runs[run_id]["status"] = "completed"
                self.active_runs[run_id]["metrics"] = final_metrics
                self.active_runs[run_id]["completed_at"] = datetime.utcnow().isoformat()
                self.active_runs[run_id]["model_path"] = str(model_path)
                self.active_runs[run_id]["dataset_checkpoint"] = str(dataset_path)
                self.active_runs[run_id]["model_slug"] = slug
                self.active_runs[run_id]["activated"] = bool(activate)

        except Exception as e:
            print(f"[train] FAILED: {e}")
            with self._lock:
                if run_id in self.active_runs:
                    self.active_runs[run_id]["status"] = "failed"
                    self.active_runs[run_id]["error"] = str(e)
            raise

    def _feature_stats(self, snaps: list[dict[str, Any]]) -> tuple[torch.Tensor, torch.Tensor]:
        """Per-feature mean/std over all training node features (for standardization)."""
        rows: list[list[float]] = []
        for snap in snaps:
            feats = snap.get("node_features") or []
            for vec in feats:
                if len(vec) == NODE_FEATURE_DIM:
                    rows.append(list(vec))
        if not rows:
            return torch.zeros(NODE_FEATURE_DIM), torch.ones(NODE_FEATURE_DIM)

        arr = np.asarray(rows, dtype=np.float64)
        mean = arr.mean(axis=0)
        std = arr.std(axis=0)
        # Keep constant/padding columns as-is (std 1) to avoid divide-by-zero blow-ups.
        std[std < 1e-6] = 1.0
        return (
            torch.tensor(mean, dtype=torch.float32),
            torch.tensor(std, dtype=torch.float32),
        )

    def _class_weights(self, snaps: list[dict[str, Any]]) -> torch.Tensor:
        """Inverse-frequency class weights over the attack taxonomy (present classes only)."""
        counts = np.zeros(len(ATTACK_TYPES), dtype=np.float64)
        for snap in snaps:
            attack_idx, _ = self._snapshot_labels(snap)
            counts[attack_idx] += 1

        present = counts > 0
        weights = np.zeros(len(ATTACK_TYPES), dtype=np.float64)
        # Inverse frequency, normalized so present-class weights average to 1.
        weights[present] = counts[present].sum() / (present.sum() * counts[present])
        return torch.tensor(weights, dtype=torch.float32)

    def _snapshot_labels(self, snap: dict[str, Any]) -> tuple[int, int]:
        attack_name = str(snap.get("attack_type", "Normal"))
        if attack_name not in ATTACK_TO_IDX:
            # Map unknown labels into closest taxonomy bucket
            lower = attack_name.lower()
            if "dos" in lower or "ddos" in lower:
                attack_name = "DoS" if "ddos" not in lower else "DDoS"
            elif "scan" in lower or "probe" in lower:
                attack_name = "Probe"
            elif "bot" in lower:
                attack_name = "Botnet"
            elif "brute" in lower or "patator" in lower:
                attack_name = "Brute Force"
            elif "web" in lower:
                attack_name = "Web Attack"
            elif "infiltrat" in lower:
                attack_name = "Infiltration"
            elif "heartbleed" in lower:
                attack_name = "Heartbleed"
            elif attack_name in ("0", "BENIGN", "benign", "Normal", "normal"):
                attack_name = "Normal"
            else:
                attack_name = "Normal" if int(snap.get("label", 0) or 0) == 0 else "DoS"

        attack_idx = ATTACK_TO_IDX.get(attack_name, 0)
        stage_idx = int(STAGE_FROM_ATTACK.get(attack_name, 2))
        stage_idx = min(max(stage_idx, 0), len(ATTACK_STAGES) - 1)
        return attack_idx, stage_idx

    def _run_epoch(
        self,
        model: TGNNModel,
        snapshots: list[dict[str, Any]],
        optimizer: torch.optim.Optimizer,
        attack_criterion: nn.Module,
        stage_criterion: nn.Module,
        *,
        train: bool,
        stage_weight: float = 0.3,
        accum_steps: int = 8,
        scaler: GradScaler | None = None,
        use_amp: bool = False,
        grad_clip: float = 5.0,
    ) -> dict[str, float]:
        if train:
            model.train()
        else:
            model.eval()

        total_loss = 0.0
        n_batches = 0
        y_true: list[int] = []
        y_pred: list[int] = []

        if train:
            optimizer.zero_grad()
        pending = 0  # snapshots accumulated since the last optimizer.step()

        context = torch.enable_grad() if train else torch.no_grad()
        with context:
            for snap in snapshots:
                feats = snap.get("node_features") or []
                if not feats:
                    continue

                x = torch.tensor(feats, dtype=torch.float32, device=self.device)
                if x.size(0) == 0:
                    continue
                if x.size(1) != NODE_FEATURE_DIM:
                    # Pad / truncate defensively
                    if x.size(1) < NODE_FEATURE_DIM:
                        pad = torch.zeros(x.size(0), NODE_FEATURE_DIM - x.size(1), device=self.device)
                        x = torch.cat([x, pad], dim=1)
                    else:
                        x = x[:, :NODE_FEATURE_DIM]

                ei_data = snap.get("edge_index") or [[0], [0]]
                if not ei_data[0]:
                    ei = torch.tensor([[0], [0]], dtype=torch.long, device=self.device)
                else:
                    ei = torch.tensor(ei_data, dtype=torch.long, device=self.device)
                    # Clamp invalid indices
                    ei = ei.clamp(min=0, max=max(x.size(0) - 1, 0))

                attack_idx, stage_idx = self._snapshot_labels(snap)
                attack_label = torch.tensor([attack_idx], dtype=torch.long, device=self.device)
                stage_label = torch.tensor([stage_idx], dtype=torch.long, device=self.device)

                with autocast(enabled=use_amp):
                    outputs = model(x, ei)
                    loss = attack_criterion(outputs["attack_logits"], attack_label) + stage_weight * stage_criterion(
                        outputs["stage_logits"], stage_label
                    )

                if train:
                    # Gradient accumulation: batch-size-1 graph updates are very
                    # noisy, so average gradients over `accum_steps` snapshots
                    # before stepping for a much more stable signal.
                    if scaler is not None and use_amp:
                        scaler.scale(loss / accum_steps).backward()
                    else:
                        (loss / accum_steps).backward()
                    pending += 1
                    if pending >= accum_steps:
                        if scaler is not None and use_amp:
                            scaler.unscale_(optimizer)
                            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=grad_clip)
                            scaler.step(optimizer)
                            scaler.update()
                        else:
                            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=grad_clip)
                            optimizer.step()
                        optimizer.zero_grad()
                        pending = 0

                total_loss += float(loss.item())
                n_batches += 1

                pred = int(outputs["attack_logits"].argmax(dim=-1).detach().cpu().item())
                y_true.append(attack_idx)
                y_pred.append(pred)

        if train and pending > 0:
            if scaler is not None and use_amp:
                scaler.unscale_(optimizer)
                torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=grad_clip)
                scaler.step(optimizer)
                scaler.update()
            else:
                torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=grad_clip)
                optimizer.step()
            optimizer.zero_grad()

        metrics = self._classification_metrics(y_true, y_pred)
        metrics["loss"] = total_loss / max(n_batches, 1)
        return metrics

    def _classification_metrics(self, y_true: list[int], y_pred: list[int]) -> dict[str, float]:
        if not y_true:
            return {"accuracy": 0.0, "precision": 0.0, "recall": 0.0, "f1": 0.0}
        return {
            "accuracy": float(accuracy_score(y_true, y_pred)),
            "precision": float(precision_score(y_true, y_pred, average="weighted", zero_division=0)),
            "recall": float(recall_score(y_true, y_pred, average="weighted", zero_division=0)),
            "f1": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        }

    def _evaluate_split(
        self, model: TGNNModel, snapshots: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Run the model over a split (no grad) collecting labels + class probabilities."""
        model.eval()
        y_true: list[int] = []
        y_pred: list[int] = []
        probs: list[np.ndarray] = []

        with torch.no_grad():
            for snap in snapshots:
                feats = snap.get("node_features") or []
                if not feats:
                    continue
                x = torch.tensor(feats, dtype=torch.float32, device=self.device)
                if x.size(0) == 0:
                    continue
                if x.size(1) != NODE_FEATURE_DIM:
                    if x.size(1) < NODE_FEATURE_DIM:
                        pad = torch.zeros(x.size(0), NODE_FEATURE_DIM - x.size(1), device=self.device)
                        x = torch.cat([x, pad], dim=1)
                    else:
                        x = x[:, :NODE_FEATURE_DIM]

                ei_data = snap.get("edge_index") or [[0], [0]]
                if not ei_data[0]:
                    ei = torch.tensor([[0], [0]], dtype=torch.long, device=self.device)
                else:
                    ei = torch.tensor(ei_data, dtype=torch.long, device=self.device)
                    ei = ei.clamp(min=0, max=max(x.size(0) - 1, 0))

                attack_idx, _ = self._snapshot_labels(snap)
                outputs = model(x, ei)
                p = torch.softmax(outputs["attack_logits"], dim=-1).detach().cpu().numpy()[0]
                probs.append(p)
                y_true.append(attack_idx)
                y_pred.append(int(p.argmax()))

        return self._comprehensive_metrics(
            y_true, y_pred, np.asarray(probs) if probs else None
        )

    def _comprehensive_metrics(
        self,
        y_true: list[int],
        y_pred: list[int],
        y_prob: np.ndarray | None,
    ) -> dict[str, Any]:
        """Full metric suite: accuracy, macro/weighted P-R-F1, ROC-AUC, confusion matrix, per-class."""
        from app.services.evaluation import enrich_evaluation

        num_classes = len(ATTACK_TYPES)
        if not y_true:
            return {
                "accuracy": 0.0,
                "weighted_precision": 0.0,
                "weighted_recall": 0.0,
                "weighted_f1": 0.0,
                "macro_precision": 0.0,
                "macro_recall": 0.0,
                "macro_f1": 0.0,
                "roc_auc": None,
                "confusion_matrix": None,
                "per_class": {},
                "class_labels": list(ATTACK_TYPES),
                "roc_curves": {},
                "pr_curves": {},
                "class_distribution": [],
            }

        acc = float(accuracy_score(y_true, y_pred))
        weighted_p = float(precision_score(y_true, y_pred, average="weighted", zero_division=0))
        weighted_r = float(recall_score(y_true, y_pred, average="weighted", zero_division=0))
        weighted_f = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))
        macro_p = float(precision_score(y_true, y_pred, average="macro", zero_division=0))
        macro_r = float(recall_score(y_true, y_pred, average="macro", zero_division=0))
        macro_f = float(f1_score(y_true, y_pred, average="macro", zero_division=0))

        present = sorted(set(y_true))
        pr, rc, f1c, sup = precision_recall_fscore_support(
            y_true, y_pred, labels=present, zero_division=0
        )
        per_class = {
            ATTACK_TYPES[c]: {
                "precision": round(float(pr[i]), 4),
                "recall": round(float(rc[i]), 4),
                "f1": round(float(f1c[i]), 4),
                "support": int(sup[i]),
            }
            for i, c in enumerate(present)
        }

        cm = confusion_matrix(y_true, y_pred, labels=list(range(num_classes))).tolist()

        roc_auc: float | None = None
        if y_prob is not None and len(present) >= 2:
            try:
                prob_present = y_prob[:, present]
                col_sums = prob_present.sum(axis=1, keepdims=True)
                col_sums[col_sums == 0] = 1.0
                prob_present = prob_present / col_sums
                y_bin = label_binarize(y_true, classes=present)
                if y_bin.shape[1] == 1:
                    roc_auc = float(roc_auc_score(y_bin.ravel(), prob_present[:, 1]))
                else:
                    roc_auc = float(
                        roc_auc_score(y_bin, prob_present, average="macro", multi_class="ovr")
                    )
            except Exception:
                roc_auc = None

        base = {
            "accuracy": round(acc, 4),
            "weighted_precision": round(weighted_p, 4),
            "weighted_recall": round(weighted_r, 4),
            "weighted_f1": round(weighted_f, 4),
            "macro_precision": round(macro_p, 4),
            "macro_recall": round(macro_r, 4),
            "macro_f1": round(macro_f, 4),
            "roc_auc": round(roc_auc, 4) if roc_auc is not None else None,
            "confusion_matrix": cm,
            "per_class": per_class,
            "class_labels": list(ATTACK_TYPES),
        }
        return enrich_evaluation(base, y_true, y_prob, class_labels=list(ATTACK_TYPES))

    def _extract_labels(self, df: pd.DataFrame) -> tuple[list[str], list[int]]:
        """Legacy helper kept for compatibility; snapshot labels are preferred."""
        attack_col = None
        for col in ["attack_type", "attack_cat", "label", "Label"]:
            if col in df.columns:
                attack_col = col
                break

        attacks, stages = [], []
        values = df[attack_col].values if attack_col else ["Normal"] * len(df)
        for val in values:
            val_str = str(val)
            if val_str in ("0", "normal", "Normal", "BENIGN", "benign"):
                attacks.append("Normal")
                stages.append(0)
            else:
                mapped = val_str if val_str in ATTACK_TO_IDX else "DoS"
                attacks.append(mapped)
                stages.append(STAGE_FROM_ATTACK.get(mapped, 2))
        return attacks, stages

    def _compute_metrics(
        self,
        attack_true: list,
        attack_pred: list,
        stage_true: list,
        stage_pred: list,
    ) -> dict[str, Any]:
        base = self._classification_metrics(attack_true, attack_pred)
        if stage_true:
            base["stage_accuracy"] = float(accuracy_score(stage_true, stage_pred))
        return {k: round(float(v), 4) for k, v in base.items()}

    def _gpu_util(self) -> float:
        if torch.cuda.is_available():
            try:
                return round(float(torch.cuda.utilization()), 2)
            except Exception:
                return 0.0
        return 0.0

    def get_metrics(self, model_id: str | None = None) -> dict[str, Any]:
        model_path = MODEL_DIR / "tgnn_model.pt"
        if model_id:
            candidate = MODEL_DIR / f"{model_id}.pt"
            if candidate.exists():
                model_path = candidate
        if model_path.exists():
            checkpoint = torch.load(model_path, map_location="cpu", weights_only=False)
            from app.services.evaluation import build_evaluation_payload

            payload = build_evaluation_payload(checkpoint, model_path)
            # Backward-compatible flat metrics dict for existing UI hooks.
            metrics = checkpoint.get("metrics", {})
            payload["metrics"] = metrics
            return payload
        return {"model_loaded": False, "metrics": {}}


training_service = TrainingService()
