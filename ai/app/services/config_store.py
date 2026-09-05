"""Persistent Model Studio configuration (Phase 1, Module C / Phase 3).

Stores the graph strategy, its parameters, the selected feature set and default
hyperparameters in a small JSON file so the frontend can save settings and have
them reload automatically on startup. Deliberately dependency-free (plain JSON)
to stay portable and easy to inspect.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from app.graph.strategies import DEFAULT_STRATEGY, GraphConfig


def _resolve_config_dir() -> Path:
    env = os.environ.get("CONFIG_DIR")
    if env:
        return Path(env).expanduser().resolve()
    return Path(__file__).resolve().parents[2] / "config"


CONFIG_DIR = _resolve_config_dir()
CONFIG_PATH = CONFIG_DIR / "studio_config.json"

# Feature toggles surfaced in Model Studio (Phase 3 will wire each into
# preprocessing; stored here so the selection persists across restarts).
DEFAULT_FEATURE_SET = {
    "timestamp": True,
    "packet_size": True,
    "protocol": True,
    "ports": True,
    "flow_duration": True,
    "tcp_flags": False,
}

DEFAULT_CONFIG: dict[str, Any] = {
    "dataset_id": "cicids2017",
    "architecture": "gat",
    "graph_strategy": DEFAULT_STRATEGY,
    "graph_params": GraphConfig(strategy=DEFAULT_STRATEGY).to_metadata(),
    "feature_set": DEFAULT_FEATURE_SET,
    "hyperparameters": {
        "learning_rate": 0.0005,
        "hidden_dim": 64,
        "max_rows": 20000,
        "epochs": 50,
        "early_stop_patience": 8,
        "grad_clip": 5.0,
        "use_amp": True,
    },
}


def _merge_defaults(cfg: dict[str, Any]) -> dict[str, Any]:
    """Return a config with any missing top-level keys filled from defaults."""
    merged = {**DEFAULT_CONFIG, **(cfg or {})}
    merged["feature_set"] = {**DEFAULT_FEATURE_SET, **(cfg.get("feature_set") or {})}
    merged["hyperparameters"] = {
        **DEFAULT_CONFIG["hyperparameters"],
        **(cfg.get("hyperparameters") or {}),
    }
    return merged


def load_config() -> dict[str, Any]:
    """Load the saved Studio config, falling back to sensible defaults."""
    if CONFIG_PATH.exists():
        try:
            data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return _merge_defaults(data)
        except (json.JSONDecodeError, OSError):
            pass
    return dict(DEFAULT_CONFIG)


def save_config(cfg: dict[str, Any]) -> dict[str, Any]:
    """Validate + persist the Studio config; returns the normalized stored config."""
    incoming = _merge_defaults(cfg or {})

    # Normalize the graph strategy/params through GraphConfig so only valid,
    # coerced values are persisted.
    graph_config = GraphConfig.from_dict(
        incoming.get("graph_strategy"), incoming.get("graph_params")
    )
    incoming["graph_strategy"] = graph_config.strategy
    incoming["graph_params"] = graph_config.to_metadata()

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(incoming, indent=2), encoding="utf-8")
    return incoming
