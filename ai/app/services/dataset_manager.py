"""Incremental dataset collection & versioning (Phase 12, step 1).

New traffic (uploads, streaming CSV, folder-watcher captures, user-labelled
attacks) is registered here. Each accepted dataset becomes an immutable version
(``dataset_v1``, ``dataset_v2``, …) stored on disk with rich metadata:

    source, date, size, attack distribution, classes, sha256 hash, quality report
    and a baseline distribution snapshot (used later for drift detection).

Safety properties (anti-poisoning):
  * content-hash **duplicate detection** — re-registering identical data returns
    the existing version instead of creating a new one;
  * every dataset is screened by :mod:`app.services.data_quality` first and
    rejected (never versioned) if it fails.

Layout::

    <DATA_DIR>/versions/<name>/index.json
    <DATA_DIR>/versions/<name>/v1/{data.csv, metadata.json}
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd

from app.services import data_quality, drift
from app.services.cl_paths import versions_dir

_MAX_STORED_ROWS = 200_000  # cap stored copy so versioning stays disk-friendly


def _safe_name(name: str) -> str:
    key = (name or "dataset").strip().lower().replace(" ", "_")
    safe = re.sub(r"[^a-z0-9_\-]", "_", key)
    return safe or "dataset"


def _dataset_dir(name: str) -> Path:
    d = versions_dir() / _safe_name(name)
    d.mkdir(parents=True, exist_ok=True)
    return d


def _content_hash(df: pd.DataFrame) -> str:
    try:
        h = hashlib.sha256(
            pd.util.hash_pandas_object(df, index=False).values.tobytes()
        )
        h.update(",".join(map(str, df.columns)).encode("utf-8"))
        return h.hexdigest()
    except Exception:
        return hashlib.sha256(df.to_csv(index=False).encode("utf-8")).hexdigest()


class DatasetManager:
    # -- registration ------------------------------------------------------

    def register_dataframe(
        self,
        name: str,
        df: pd.DataFrame,
        source: str = "upload",
        expected_features: list[str] | None = None,
        note: str | None = None,
    ) -> dict[str, Any]:
        """Screen, de-duplicate and version a dataframe. Returns the outcome."""
        content_hash = _content_hash(df)

        # Duplicate detection against every existing version of this dataset.
        existing = self._find_by_hash(name, content_hash)
        if existing is not None:
            return {
                "status": "duplicate",
                "accepted": False,
                "message": f"Identical data already stored as {existing['version']}.",
                "version": existing["version"],
                "hash": content_hash,
                "metadata": existing,
            }

        report = data_quality.analyze(df, expected_features=expected_features)
        if not report["passed"]:
            return {
                "status": "rejected",
                "accepted": False,
                "message": "Dataset failed quality checks and was not versioned.",
                "hash": content_hash,
                "quality_report": report,
            }

        version_no = self._next_version_number(name)
        version_id = f"{_safe_name(name)}_v{version_no}"
        vdir = _dataset_dir(name) / f"v{version_no}"
        vdir.mkdir(parents=True, exist_ok=True)

        stored = df.head(_MAX_STORED_ROWS)
        data_path = vdir / "data.csv"
        try:
            stored.to_csv(data_path, index=False)
        except OSError as exc:  # pragma: no cover - disk failure
            return {"status": "error", "accepted": False, "message": str(exc)}

        baseline = drift.compute_baseline(stored)
        metadata = {
            "version": version_id,
            "version_number": version_no,
            "name": _safe_name(name),
            "display_name": name,
            "source": source,
            "created_at": datetime.utcnow().isoformat(),
            "rows": int(len(df)),
            "stored_rows": int(len(stored)),
            "columns": int(df.shape[1]),
            "hash": content_hash,
            "classes": sorted(report.get("class_distribution", {}).keys()),
            "attack_distribution": report.get("class_distribution", {}),
            "quality_report": report,
            "baseline": baseline,
            "data_file": str(data_path),
            "note": note,
        }
        (vdir / "metadata.json").write_text(
            json.dumps(metadata, indent=2, default=str), encoding="utf-8"
        )
        self._append_index(name, metadata)

        # A listing-friendly copy without the (large) baseline/quality internals.
        return {
            "status": "accepted",
            "accepted": True,
            "message": f"Registered as {version_id}.",
            "version": version_id,
            "hash": content_hash,
            "metadata": self._summarize(metadata),
            "quality_report": report,
        }

    def register_csv(
        self, name: str, csv_path: str, source: str = "upload", max_rows: int = 200_000
    ) -> dict[str, Any]:
        df = pd.read_csv(csv_path, nrows=max_rows)
        return self.register_dataframe(name, df, source=source)

    # -- querying ----------------------------------------------------------

    def list_versions(self, name: str | None = None) -> dict[str, Any]:
        datasets: list[dict[str, Any]] = []
        root = versions_dir()
        names = [name] if name else [p.name for p in root.iterdir() if p.is_dir()]
        for ds_name in names:
            versions = self._read_index(ds_name)
            if not versions:
                continue
            datasets.append({
                "name": _safe_name(ds_name),
                "display_name": versions[-1].get("display_name", ds_name),
                "latest_version": versions[-1].get("version"),
                "version_count": len(versions),
                "versions": [self._summarize(v) for v in versions],
            })
        datasets.sort(key=lambda d: d["name"])
        return {"datasets": datasets, "root": str(root)}

    def history(self) -> list[dict[str, Any]]:
        """Flat, chronological history of every registered version."""
        out: list[dict[str, Any]] = []
        for p in versions_dir().iterdir():
            if p.is_dir():
                out.extend(self._summarize(v) for v in self._read_index(p.name))
        out.sort(key=lambda v: str(v.get("created_at", "")), reverse=True)
        return out

    def get_version(self, name: str, version: str | int | None = None) -> dict[str, Any] | None:
        versions = self._read_index(name)
        if not versions:
            return None
        if version is None:
            return versions[-1]
        target = str(version)
        for v in versions:
            if v.get("version") == target or str(v.get("version_number")) == target:
                return v
        return None

    def get_baseline(self, name: str) -> dict[str, Any] | None:
        latest = self.get_version(name)
        return latest.get("baseline") if latest else None

    def load_version_dataframe(self, name: str, version: str | int | None = None) -> pd.DataFrame | None:
        meta = self.get_version(name, version)
        if not meta:
            return None
        path = meta.get("data_file")
        if path and Path(path).exists():
            return pd.read_csv(path)
        return None

    # -- internals ---------------------------------------------------------

    def _summarize(self, meta: dict[str, Any]) -> dict[str, Any]:
        report = meta.get("quality_report") or {}
        return {
            "version": meta.get("version"),
            "version_number": meta.get("version_number"),
            "name": meta.get("name"),
            "display_name": meta.get("display_name"),
            "source": meta.get("source"),
            "created_at": meta.get("created_at"),
            "rows": meta.get("rows"),
            "columns": meta.get("columns"),
            "hash": meta.get("hash"),
            "classes": meta.get("classes"),
            "attack_distribution": meta.get("attack_distribution"),
            "quality_score": report.get("score"),
            "quality_passed": report.get("passed"),
            "note": meta.get("note"),
        }

    def _index_path(self, name: str) -> Path:
        return _dataset_dir(name) / "index.json"

    def _read_index(self, name: str) -> list[dict[str, Any]]:
        path = self._index_path(name)
        if not path.exists():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
        except (json.JSONDecodeError, OSError):
            return []

    def _append_index(self, name: str, metadata: dict[str, Any]) -> None:
        index = self._read_index(name)
        index.append(metadata)
        try:
            self._index_path(name).write_text(
                json.dumps(index, indent=2, default=str), encoding="utf-8"
            )
        except OSError:
            pass

    def _next_version_number(self, name: str) -> int:
        index = self._read_index(name)
        return (max((v.get("version_number", 0) for v in index), default=0)) + 1

    def _find_by_hash(self, name: str, content_hash: str) -> dict[str, Any] | None:
        for v in self._read_index(name):
            if v.get("hash") == content_hash:
                return v
        return None


dataset_manager = DatasetManager()
