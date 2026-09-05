"""Phase 2 training entrypoint: CICIDS2017 → temporal graphs → TGNN checkpoint."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Train TGNN on local CICIDS2017")
    parser.add_argument("--epochs", type=int, default=8)
    parser.add_argument("--max-rows", type=int, default=8000)
    parser.add_argument("--hidden-dim", type=int, default=64)
    parser.add_argument("--lr", type=float, default=0.001)
    parser.add_argument("--architecture", type=str, default="gat", choices=["gat", "graphsage", "gcn"])
    parser.add_argument("--window-seconds", type=int, default=30)
    args = parser.parse_args()

    # Ensure `app` package imports resolve when run as a script
    ai_root = Path(__file__).resolve().parent
    if str(ai_root) not in sys.path:
        sys.path.insert(0, str(ai_root))

    # Prefer repo DataSet / ai/models unless already set
    repo_root = ai_root.parent
    os.environ.setdefault("DATASET_ROOT", str(repo_root / "DataSet"))
    os.environ.setdefault("MODEL_DIR", str(ai_root / "models"))

    from app.services.training import training_service

    result = training_service.train_sync(
        dataset_id="cicids2017",
        architecture=args.architecture,
        epochs=args.epochs,
        hidden_dim=args.hidden_dim,
        learning_rate=args.lr,
        max_rows=args.max_rows,
        window_seconds=args.window_seconds,
    )

    if result.get("status") != "completed":
        print("[train_cicids] Training failed:", result.get("error"))
        return 1

    print("[train_cicids] Status:", result["status"])
    print("[train_cicids] Model:", result.get("model_path"))
    print("[train_cicids] Metrics:", result.get("metrics"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
