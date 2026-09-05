"""Filesystem layout for the Phase 12 continual-learning platform.

All continual-learning artefacts live under a single data root so they are easy
to back up, inspect and reset:

    <DATA_DIR or ai/data>/
        versions/            # versioned datasets (dataset_v1, dataset_v2, ...)
        drift/               # drift-detection reports
        review/              # confidence-based / active-learning review queue
        knowledge_base.json  # AI knowledge base cache
    ai/experiments/          # append-only experiment tracking log

These helpers are intentionally dependency-free so every service can import them
without side effects, and they create directories lazily on first use.
"""

from __future__ import annotations

import os
from pathlib import Path


def ai_root() -> Path:
    """Return the ``ai/`` package root (…/ai)."""
    return Path(__file__).resolve().parents[2]


def data_dir() -> Path:
    """Root for all persisted continual-learning data (honours ``DATA_DIR``)."""
    env = os.environ.get("DATA_DIR")
    base = Path(env).expanduser().resolve() if env else ai_root() / "data"
    base.mkdir(parents=True, exist_ok=True)
    return base


def versions_dir() -> Path:
    d = data_dir() / "versions"
    d.mkdir(parents=True, exist_ok=True)
    return d


def drift_dir() -> Path:
    d = data_dir() / "drift"
    d.mkdir(parents=True, exist_ok=True)
    return d


def review_dir() -> Path:
    d = data_dir() / "review"
    d.mkdir(parents=True, exist_ok=True)
    return d


def replay_dir() -> Path:
    d = data_dir() / "replay"
    d.mkdir(parents=True, exist_ok=True)
    return d


def experiments_dir() -> Path:
    d = ai_root() / "experiments"
    d.mkdir(parents=True, exist_ok=True)
    return d


def knowledge_base_path() -> Path:
    return data_dir() / "knowledge_base.json"
