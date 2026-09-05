"""Experience replay buffer (Phase 10–11).

Stores labelled traffic rows for rehearsal during incremental retraining so the
model sees a mix of new and historical samples — a lightweight guard against
catastrophic forgetting without changing the TGNN architecture.

Rows are append-only JSONL under ``ai/data/replay/``. Approved review-queue
samples and explicit ``add_rows`` calls both feed the buffer.
"""

from __future__ import annotations

import json
import random
import uuid
from datetime import datetime
from typing import Any

from app.services.cl_paths import replay_dir

_MAX_ENTRIES = 10000


class ReplayBuffer:
    def __init__(self) -> None:
        self._path = replay_dir() / "replay_buffer.jsonl"

    def add_rows(self, rows: list[dict[str, Any]], source: str = "manual") -> int:
        """Append rows; returns count added."""
        added = 0
        for row in rows:
            if not row:
                continue
            entry = {
                "id": str(uuid.uuid4()),
                "stored_at": datetime.utcnow().isoformat(),
                "source": source,
                "row": row,
            }
            if self._count() >= _MAX_ENTRIES:
                break
            self._append(entry)
            added += 1
        return added

    def add_from_review_sample(self, sample: dict[str, Any]) -> bool:
        """Convert an approved review-queue sample into a replay row."""
        label = sample.get("true_label") or sample.get("predicted_attack_type")
        features = sample.get("features") or {}
        if not label or not isinstance(features, dict):
            return False
        row = dict(features)
        row["Label"] = label
        row["attack_type"] = label
        return self.add_rows([row], source=f"review:{sample.get('id', 'unknown')}") > 0

    def sample(self, n: int = 100, seed: int | None = None) -> list[dict[str, Any]]:
        rows = self._read_all()
        if not rows:
            return []
        rng = random.Random(seed)
        picked = rows if len(rows) <= n else rng.sample(rows, n)
        return [r.get("row") or {} for r in picked if r.get("row")]

    def stats(self) -> dict[str, Any]:
        rows = self._read_all()
        by_source: dict[str, int] = {}
        for r in rows:
            src = str(r.get("source", "unknown"))
            by_source[src] = by_source.get(src, 0) + 1
        return {
            "total": len(rows),
            "capacity": _MAX_ENTRIES,
            "by_source": by_source,
        }

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


replay_buffer = ReplayBuffer()
