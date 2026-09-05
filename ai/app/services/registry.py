"""Model registry (Phase 2).

Treats the on-disk checkpoints in ``MODEL_DIR`` as the source of truth and layers
a lightweight, human-readable registry on top:

  * per-dataset checkpoints ``{slug}.pt`` are the registered models (id = slug),
  * ``tgnn_model.pt`` is the *active* model the inference service loads,
  * a JSON sidecar ``{slug}.json`` caches metadata so listing is fast (no need to
    torch.load every checkpoint).

Capabilities: list, activate (switch), delete and export-metadata. Deliberately
filesystem-based so it works without extra infrastructure and stays in sync with
what training actually produces.
"""

from __future__ import annotations

import json
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

import torch

ACTIVE_FILENAME = "tgnn_model.pt"
PREVIOUS_ACTIVE_FILENAME = "previous_active.pt"
PREVIOUS_ACTIVE_META = "previous_active.json"


def _resolve_model_dir() -> Path:
    env = os.environ.get("MODEL_DIR")
    if env:
        path = Path(env).expanduser()
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


def _summarize_metrics(metrics: dict[str, Any]) -> dict[str, Any]:
    """Compact metrics for registry listings (drop bulky history)."""
    if not isinstance(metrics, dict):
        return {}
    test = metrics.get("test") or {}
    return {
        "accuracy": metrics.get("accuracy"),
        "f1": metrics.get("f1"),
        "test_accuracy": test.get("accuracy"),
        "test_f1": test.get("f1"),
        "macro_f1": metrics.get("macro_f1") or test.get("macro_f1"),
        "roc_auc": metrics.get("roc_auc") or test.get("roc_auc"),
        "best_epoch": metrics.get("best_epoch"),
        "graph_stats": metrics.get("graph_stats"),
        "training_time_sec": metrics.get("training_time_sec"),
        "inference_time_ms": metrics.get("inference_time_ms"),
    }


class ModelRegistry:
    def __init__(self) -> None:
        self.model_dir = _resolve_model_dir()

    # -- sidecar helpers ---------------------------------------------------

    def _sidecar_path(self, model_id: str) -> Path:
        return self.model_dir / f"{model_id}.json"

    def _checkpoint_path(self, model_id: str) -> Path:
        return self.model_dir / f"{model_id}.pt"

    def write_sidecar(self, model_id: str, checkpoint: dict[str, Any]) -> None:
        """Persist a metadata sidecar next to a checkpoint (called after training)."""
        ckpt_path = self._checkpoint_path(model_id)
        meta = self._metadata_from_checkpoint(model_id, checkpoint, ckpt_path)
        try:
            self._sidecar_path(model_id).write_text(
                json.dumps(meta, indent=2, default=str), encoding="utf-8"
            )
        except OSError:
            pass

    def _metadata_from_checkpoint(
        self, model_id: str, checkpoint: dict[str, Any], ckpt_path: Path
    ) -> dict[str, Any]:
        metrics = checkpoint.get("metrics") or {}
        size_bytes = ckpt_path.stat().st_size if ckpt_path.exists() else 0
        return {
            "id": model_id,
            "name": f"TGNN · {checkpoint.get('dataset_id') or model_id}",
            "dataset_id": checkpoint.get("dataset_id"),
            "architecture": checkpoint.get("architecture", "gat"),
            "hidden_dim": checkpoint.get("hidden_dim"),
            "node_features": checkpoint.get("node_features"),
            "graph_strategy": checkpoint.get("graph_strategy")
            or metrics.get("graph_strategy"),
            "graph_params": checkpoint.get("graph_params") or metrics.get("graph_params"),
            "feature_set": checkpoint.get("feature_set") or metrics.get("feature_set"),
            "trained_at": checkpoint.get("trained_at"),
            "metrics": _summarize_metrics(metrics),
            "file": ckpt_path.name,
            "size_bytes": size_bytes,
        }

    def _load_metadata(self, model_id: str) -> dict[str, Any]:
        """Return metadata for a model, using the sidecar or synthesizing it."""
        sidecar = self._sidecar_path(model_id)
        ckpt_path = self._checkpoint_path(model_id)
        if sidecar.exists():
            try:
                data = json.loads(sidecar.read_text(encoding="utf-8"))
                # Refresh the (cheap) file size in case it changed.
                if ckpt_path.exists():
                    data["size_bytes"] = ckpt_path.stat().st_size
                return data
            except (json.JSONDecodeError, OSError):
                pass
        # Fall back to a one-time checkpoint read, then cache a sidecar.
        checkpoint = torch.load(ckpt_path, map_location="cpu", weights_only=False)
        meta = self._metadata_from_checkpoint(model_id, checkpoint, ckpt_path)
        try:
            sidecar.write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")
        except OSError:
            pass
        return meta

    # -- active model fingerprint -----------------------------------------

    def _active_fingerprint(self) -> tuple[str | None, str | None]:
        active = self.model_dir / ACTIVE_FILENAME
        if not active.exists():
            return (None, None)
        try:
            ckpt = torch.load(active, map_location="cpu", weights_only=False)
            return (ckpt.get("dataset_id"), ckpt.get("trained_at"))
        except Exception:
            return (None, None)

    # -- public API --------------------------------------------------------

    def list_models(self) -> dict[str, Any]:
        self.model_dir.mkdir(parents=True, exist_ok=True)
        active_dataset, active_trained_at = self._active_fingerprint()
        models: list[dict[str, Any]] = []
        for ckpt_path in sorted(self.model_dir.glob("*.pt")):
            # Skip the active copy, rollback snapshot, legacy backups and any
            # tgnn_model* aliases — registered models are per-dataset ({slug}.pt).
            stem = ckpt_path.stem
            if (
                ckpt_path.name == ACTIVE_FILENAME
                or ckpt_path.name == PREVIOUS_ACTIVE_FILENAME
                or stem.startswith("tgnn_model")
                or "backup" in stem.lower()
                or not stem
            ):
                continue
            model_id = stem
            try:
                meta = self._load_metadata(model_id)
            except Exception as exc:  # noqa: BLE001 - keep listing resilient
                meta = {
                    "id": model_id,
                    "name": model_id,
                    "file": ckpt_path.name,
                    "size_bytes": ckpt_path.stat().st_size,
                    "error": str(exc),
                }
            meta["is_active"] = bool(
                meta.get("dataset_id") == active_dataset
                and meta.get("trained_at") == active_trained_at
                and active_dataset is not None
            )
            models.append(meta)
        return {
            "models": models,
            "active": {"dataset_id": active_dataset, "trained_at": active_trained_at},
            "model_dir": str(self.model_dir),
        }

    def get_metadata(self, model_id: str) -> dict[str, Any]:
        if not self._checkpoint_path(model_id).exists():
            raise FileNotFoundError(f"Model '{model_id}' not found")
        return self._load_metadata(model_id)

    def _backup_active(self) -> dict[str, Any] | None:
        """Snapshot the current active checkpoint before promotion."""
        active = self.model_dir / ACTIVE_FILENAME
        if not active.exists():
            return None
        backup = self.model_dir / PREVIOUS_ACTIVE_FILENAME
        meta_path = self.model_dir / PREVIOUS_ACTIVE_META
        previous_id: str | None = None
        try:
            ckpt = torch.load(active, map_location="cpu", weights_only=False)
            dataset_id = ckpt.get("dataset_id")
            trained_at = ckpt.get("trained_at")
            for sidecar in self.model_dir.glob("*.json"):
                if sidecar.name == PREVIOUS_ACTIVE_META:
                    continue
                try:
                    data = json.loads(sidecar.read_text(encoding="utf-8"))
                    if data.get("dataset_id") == dataset_id and data.get("trained_at") == trained_at:
                        previous_id = data.get("id")
                        break
                except (json.JSONDecodeError, OSError):
                    continue
            shutil.copyfile(active, backup)
            info = {
                "backed_up_at": datetime.utcnow().isoformat(),
                "previous_model_id": previous_id,
                "dataset_id": dataset_id,
                "trained_at": trained_at,
                "backup_file": backup.name,
            }
            meta_path.write_text(json.dumps(info, indent=2, default=str), encoding="utf-8")
            return info
        except Exception:
            return None

    def rollback_info(self) -> dict[str, Any]:
        backup = self.model_dir / PREVIOUS_ACTIVE_FILENAME
        meta_path = self.model_dir / PREVIOUS_ACTIVE_META
        if not backup.exists():
            return {"available": False, "message": "No previous active checkpoint on disk."}
        meta: dict[str, Any] = {}
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                meta = {}
        return {
            "available": True,
            "backup_file": backup.name,
            "size_bytes": backup.stat().st_size,
            **meta,
        }

    def rollback(self) -> dict[str, Any]:
        """Restore the last active checkpoint from ``previous_active.pt``."""
        backup = self.model_dir / PREVIOUS_ACTIVE_FILENAME
        if not backup.exists():
            raise FileNotFoundError("No previous active checkpoint to roll back to")
        active = self.model_dir / ACTIVE_FILENAME
        # Preserve current active as a timestamped safety copy before rollback.
        if active.exists():
            stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
            safety = self.model_dir / f"tgnn_model__pre_rollback_{stamp}.pt"
            try:
                shutil.copyfile(active, safety)
            except OSError:
                pass
        shutil.copyfile(backup, active)
        from app.services.inference import inference_service

        info = inference_service.reload()
        meta = self.rollback_info()
        return {
            "rolled_back": True,
            "restored_from": backup.name,
            "previous_model_id": meta.get("previous_model_id"),
            "model_info": info,
        }

    def activate(self, model_id: str) -> dict[str, Any]:
        ckpt_path = self._checkpoint_path(model_id)
        if not ckpt_path.exists():
            raise FileNotFoundError(f"Model '{model_id}' not found")
        backup_info = self._backup_active()
        active = self.model_dir / ACTIVE_FILENAME
        shutil.copyfile(ckpt_path, active)
        # Hot-reload the inference service so the switch takes effect immediately.
        from app.services.inference import inference_service

        info = inference_service.reload()
        result = {"activated": model_id, "model_info": info}
        if backup_info:
            result["previous_active"] = backup_info
        return result

    def delete(self, model_id: str) -> dict[str, Any]:
        ckpt_path = self._checkpoint_path(model_id)
        if not ckpt_path.exists():
            raise FileNotFoundError(f"Model '{model_id}' not found")
        active_dataset, active_trained_at = self._active_fingerprint()
        meta = self._load_metadata(model_id)
        was_active = bool(
            meta.get("dataset_id") == active_dataset
            and meta.get("trained_at") == active_trained_at
        )
        ckpt_path.unlink(missing_ok=True)
        self._sidecar_path(model_id).unlink(missing_ok=True)
        return {
            "deleted": model_id,
            "was_active": was_active,
            "note": (
                "The active checkpoint (tgnn_model.pt) is a copy and is unaffected; "
                "activate another model to change what inference loads."
                if was_active
                else "Deleted."
            ),
        }

    def export_metadata(self, model_id: str) -> dict[str, Any]:
        """Full metadata for export (includes an export timestamp)."""
        meta = self.get_metadata(model_id)
        return {**meta, "exported_at": datetime.utcnow().isoformat()}

    def checkpoint_file(self, model_id: str) -> Path:
        ckpt_path = self._checkpoint_path(model_id)
        if not ckpt_path.exists():
            raise FileNotFoundError(f"Model '{model_id}' not found")
        return ckpt_path


model_registry = ModelRegistry()
