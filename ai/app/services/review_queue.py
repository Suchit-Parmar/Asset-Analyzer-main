"""Confidence-based & active learning review queue (Phase 12, steps 7 & 8).

Records predictions the model is unsure about so a human can review them:

  * low-confidence predictions,
  * predictions on traffic that looks unknown/out-of-distribution.

A reviewer can relabel a sample and approve it; approved samples become training
material for the next candidate model. Active learning is served by
:meth:`select_uncertain`, which returns the lowest-confidence pending samples —
labelling those yields the largest expected improvement per human effort.

Backed by an append-only JSONL file with a hard size cap so a busy inference
service can capture samples without unbounded disk growth.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any

from app.services.cl_paths import review_dir

_MAX_ENTRIES = 5000
_DEFAULT_CONFIDENCE_THRESHOLD = 0.5


class ReviewQueue:
    def __init__(self) -> None:
        self._path = review_dir() / "review_queue.jsonl"

    # -- capture -----------------------------------------------------------

    def record_prediction(
        self,
        prediction: dict[str, Any],
        *,
        confidence_threshold: float = _DEFAULT_CONFIDENCE_THRESHOLD,
        source: str = "inference",
    ) -> dict[str, Any] | None:
        """Best-effort capture of a low-confidence/unknown prediction.

        Returns the stored entry, or ``None`` if the prediction was confident
        enough to skip (or the queue is full). Never raises.
        """
        try:
            confidence = float(prediction.get("confidence") or 0.0)
            attack_type = prediction.get("attack_type")
            unknown = bool(prediction.get("is_unknown"))
            if confidence >= confidence_threshold and not unknown:
                return None
            if self._count() >= _MAX_ENTRIES:
                return None

            entry = {
                "id": str(uuid.uuid4()),
                "captured_at": datetime.utcnow().isoformat(),
                "source": source,
                "status": "pending",
                "confidence": round(confidence, 4),
                "predicted_attack_type": attack_type,
                "threat_level": prediction.get("threat_level"),
                "reason": "unknown_traffic" if unknown else "low_confidence",
                "true_label": None,
                "features": prediction.get("features") or {},
                "graph": prediction.get("graph") or {},
                "dataset_id": prediction.get("dataset_id"),
            }
            self._append(entry)
            return entry
        except Exception:
            return None

    # -- review ------------------------------------------------------------

    def list(self, status: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        rows = self._read_all()
        if status:
            rows = [r for r in rows if r.get("status") == status]
        rows.sort(key=lambda r: str(r.get("captured_at", "")), reverse=True)
        return rows[:limit]

    def select_uncertain(self, limit: int = 20) -> list[dict[str, Any]]:
        """Active learning: the most uncertain pending samples first."""
        pending = [r for r in self._read_all() if r.get("status") == "pending"]
        pending.sort(key=lambda r: float(r.get("confidence") or 0.0))
        return pending[:limit]

    def relabel(self, sample_id: str, true_label: str) -> dict[str, Any]:
        return self._update(sample_id, {"true_label": true_label, "status": "labeled"})

    def approve(self, sample_id: str) -> dict[str, Any]:
        return self._update(sample_id, {"status": "approved"})

    def reject(self, sample_id: str) -> dict[str, Any]:
        return self._update(sample_id, {"status": "rejected"})

    def approved_samples(self) -> list[dict[str, Any]]:
        return [r for r in self._read_all() if r.get("status") == "approved"]

    def stats(self) -> dict[str, Any]:
        rows = self._read_all()
        by_status: dict[str, int] = {}
        for r in rows:
            by_status[r.get("status", "pending")] = by_status.get(r.get("status", "pending"), 0) + 1
        return {
            "total": len(rows),
            "pending": by_status.get("pending", 0),
            "labeled": by_status.get("labeled", 0),
            "approved": by_status.get("approved", 0),
            "rejected": by_status.get("rejected", 0),
            "capacity": _MAX_ENTRIES,
        }

    # -- internals ---------------------------------------------------------

    def _update(self, sample_id: str, patch: dict[str, Any]) -> dict[str, Any]:
        rows = self._read_all()
        updated: dict[str, Any] | None = None
        for r in rows:
            if r.get("id") == sample_id:
                r.update(patch)
                r["updated_at"] = datetime.utcnow().isoformat()
                updated = r
                break
        if updated is None:
            raise KeyError(f"Review sample '{sample_id}' not found")
        self._rewrite(rows)
        return updated

    def _count(self) -> int:
        if not self._path.exists():
            return 0
        try:
            with self._path.open("r", encoding="utf-8") as fh:
                return sum(1 for line in fh if line.strip())
        except OSError:
            return 0

    def _append(self, entry: dict[str, Any]) -> None:
        try:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
        except OSError:
            pass

    def _rewrite(self, rows: list[dict[str, Any]]) -> None:
        try:
            with self._path.open("w", encoding="utf-8") as fh:
                for r in rows:
                    fh.write(json.dumps(r, default=str) + "\n")
        except OSError:
            pass

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


review_queue = ReviewQueue()
