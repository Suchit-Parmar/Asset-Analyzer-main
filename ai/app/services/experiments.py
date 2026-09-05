"""Experiment tracking (Phase 12, step 12).

Every training run — full retrain, incremental fine-tune, transfer or candidate —
is recorded here as an append-only JSONL log. Each record captures enough to
reproduce and compare a run: hyperparameters, dataset, graph strategy,
architecture, metrics, timings, checkpoint and (optionally) the git commit.

Append-only + line-delimited keeps writes atomic and the history immutable, which
is exactly what a research audit trail needs.
"""

from __future__ import annotations

import json
import subprocess
import uuid
from datetime import datetime
from typing import Any

from app.services.cl_paths import experiments_dir


def _git_commit() -> str | None:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=3,
        )
        if out.returncode == 0:
            return out.stdout.strip() or None
    except Exception:
        pass
    return None


class ExperimentStore:
    def __init__(self) -> None:
        self._path = experiments_dir() / "experiments.jsonl"

    def record(self, record: dict[str, Any]) -> dict[str, Any]:
        """Persist one experiment record and return it (with id/timestamp/commit)."""
        entry = {
            "id": record.get("id") or str(uuid.uuid4()),
            "recorded_at": datetime.utcnow().isoformat(),
            "git_commit": record.get("git_commit") or _git_commit(),
            **record,
        }
        try:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
        except OSError:
            pass
        return entry

    def list(
        self, limit: int = 200, dataset_id: str | None = None
    ) -> list[dict[str, Any]]:
        rows = self._read_all()
        if dataset_id:
            rows = [r for r in rows if r.get("dataset_id") == dataset_id]
        rows.sort(key=lambda r: str(r.get("recorded_at", "")), reverse=True)
        return rows[:limit]

    def get(self, experiment_id: str) -> dict[str, Any] | None:
        for row in self._read_all():
            if row.get("id") == experiment_id:
                return row
        return None

    def accuracy_trend(self, dataset_id: str | None = None) -> list[dict[str, Any]]:
        """Chronological (accuracy, f1) points for the model-evolution chart."""
        rows = self.list(limit=1000, dataset_id=dataset_id)
        rows = sorted(rows, key=lambda r: str(r.get("recorded_at", "")))
        trend = []
        for r in rows:
            m = r.get("metrics") or {}
            test = m.get("test") or {}
            trend.append({
                "id": r.get("id"),
                "recorded_at": r.get("recorded_at"),
                "dataset_id": r.get("dataset_id"),
                "architecture": r.get("architecture"),
                "mode": r.get("mode"),
                "accuracy": test.get("accuracy", m.get("accuracy")),
                "f1": test.get("f1", m.get("f1")),
                "macro_f1": m.get("macro_f1") or test.get("macro_f1"),
                "roc_auc": m.get("roc_auc") or test.get("roc_auc"),
            })
        return trend

    def _read_all(self) -> list[dict[str, Any]]:
        if not self._path.exists():
            return []
        rows: list[dict[str, Any]] = []
        try:
            for line in self._path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        except OSError:
            return []
        return rows


class ApprovalStore:
    """Append-only log of explicit model promotions (Phase 9)."""

    def __init__(self) -> None:
        self._path = experiments_dir() / "approvals.jsonl"

    def record(self, record: dict[str, Any]) -> dict[str, Any]:
        entry = {
            "id": record.get("id") or str(uuid.uuid4()),
            "approved_at": datetime.utcnow().isoformat(),
            **record,
        }
        try:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
        except OSError:
            pass
        return entry

    def list(self, limit: int = 100) -> list[dict[str, Any]]:
        if not self._path.exists():
            return []
        rows: list[dict[str, Any]] = []
        try:
            for line in self._path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        except OSError:
            return []
        rows.sort(key=lambda r: str(r.get("approved_at", "")), reverse=True)
        return rows[:limit]


experiment_store = ExperimentStore()
approval_store = ApprovalStore()
