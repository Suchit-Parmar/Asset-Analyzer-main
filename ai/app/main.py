"""FastAPI application for TGNN cyber attack prediction.

Production notes:
- Loads Phase 2 checkpoint from MODEL_DIR/tgnn_model.pt on startup.
- Express proxies authenticated traffic to these /api/v1/* routes.
- Do not change response field names without updating server/ai-client.ts.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd
import torch
from fastapi import FastAPI, File, Form, HTTPException, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.graph.strategies import (
    GRAPH_STRATEGIES,
    GraphConfig,
    build_one_snapshot,
)
from app.services import continual, knowledge_base, reports
from app.services.cl_paths import drift_dir
from app.services.config_store import load_config, save_config
from app.services.dataset_manager import dataset_manager
from app.services.experiments import experiment_store
from app.services.explainability import explainability_service
from app.services.inference import inference_service
from app.services.registry import model_registry
from app.services.review_queue import review_queue
from app.services.risk_engine import risk_engine
from app.services.training import training_service

logger = logging.getLogger("gnn-ids.ai")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s %(message)s")

app = FastAPI(
    title="GNN-IDS AI Service",
    description="Temporal Graph Neural Network for Cyber Attack Prediction",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = Path(os.environ.get("DATA_DIR", "./data")) / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


class PredictRequest(BaseModel):
    features: dict[str, Any] = Field(default_factory=dict)
    graph_snapshot: dict[str, Any] | None = None


class BatchPredictRequest(BaseModel):
    records: list[dict[str, Any]]


class ExplainRequest(BaseModel):
    node_id: str
    graph_snapshot: dict[str, Any]


class TrainRequest(BaseModel):
    run_id: str | None = None
    dataset_id: str = "cicids2017"
    architecture: str = "gat"
    hyperparameters: dict[str, Any] = Field(default_factory=dict)
    epochs: int = 50
    graph_strategy: str | None = None
    graph_params: dict[str, Any] = Field(default_factory=dict)
    feature_set: dict[str, bool] | None = None


class GraphBuildRequest(BaseModel):
    dataset_id: str
    window_seconds: int = 30
    graph_strategy: str | None = None
    graph_params: dict[str, Any] = Field(default_factory=dict)
    feature_set: dict[str, bool] | None = None


class PredictDatasetRequest(BaseModel):
    dataset_id: str = "cicids2017"
    window_seconds: int = 30
    max_rows: int = 5000
    graph_strategy: str | None = None
    graph_params: dict[str, Any] = Field(default_factory=dict)
    feature_set: dict[str, bool] | None = None


class StudioConfigRequest(BaseModel):
    config: dict[str, Any] = Field(default_factory=dict)


class RiskComputeRequest(BaseModel):
    entity_type: str
    entity_id: str
    graph_snapshot: dict[str, Any]


@app.on_event("startup")
def on_startup():
    """Ensure Phase 2 checkpoint is loaded when the inference service starts."""
    info = inference_service.get_info()
    logger.info(
        "TGNN inference ready model_loaded=%s path=%s arch=%s dataset=%s",
        info.get("model_loaded"),
        info.get("model_path"),
        info.get("architecture"),
        info.get("dataset_id"),
    )
    print(
        f"[startup] TGNN inference ready | model_loaded={info.get('model_loaded')} "
        f"| path={info.get('model_path')} | arch={info.get('architecture')}"
    )


@app.get("/")
def root():
    """Landing page for the AI service (avoids a confusing 404 on /)."""
    info = inference_service.get_info()
    return {
        "service": "GNN-IDS AI Service",
        "version": "1.0.0",
        "status": "healthy" if info.get("model_loaded") else "degraded",
        "model_loaded": bool(info.get("model_loaded")),
        "architecture": info.get("architecture"),
        "dataset_id": info.get("dataset_id"),
        "device": str(inference_service.device),
        "gpu_available": torch.cuda.is_available(),
        "message": (
            "This is the TGNN AI backend (JSON API), not the web UI. "
            "Open the SOC dashboard at http://localhost:5000"
        ),
        "links": {
            "health": "/health",
            "docs": "/docs",
            "redoc": "/redoc",
            "model_info": "/api/v1/model/info",
            "web_app": "http://localhost:5000",
        },
    }


@app.get("/health")
def health_check():
    from app.services.system_monitor import snapshot as system_snapshot

    info = inference_service.get_info()
    return {
        "status": "healthy" if info.get("model_loaded") else "degraded",
        "model_loaded": bool(info.get("model_loaded")),
        "gpu_available": torch.cuda.is_available(),
        "device": str(inference_service.device),
        "architecture": info.get("architecture"),
        "dataset_id": info.get("dataset_id"),
        "trained_at": info.get("trained_at"),
        "system": system_snapshot(),
    }


@app.get("/api/v1/admin/system")
def admin_system():
    """Detailed CPU/RAM/disk/GPU metrics for the Admin Panel."""
    from app.services.system_monitor import snapshot

    return {"system": snapshot(), "timestamp": datetime.utcnow().isoformat()}


@app.get("/api/v1/model/info")
def model_info():
    return inference_service.get_info()


@app.get("/api/v1/models")
def list_models():
    """Model registry: all trained checkpoints with metadata (Phase 2)."""
    try:
        return model_registry.list_models()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/models/{model_id}/metadata")
def model_metadata(model_id: str):
    try:
        return model_registry.export_metadata(model_id)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/models/{model_id}/activate")
def activate_model(model_id: str):
    try:
        return model_registry.activate(model_id)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/v1/models/{model_id}")
def delete_model(model_id: str):
    try:
        return model_registry.delete(model_id)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/model/reload")
def model_reload():
    try:
        return inference_service.reload()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/predict")
def predict(req: PredictRequest):
    if not inference_service.is_loaded:
        raise HTTPException(
            status_code=503,
            detail="TGNN model not loaded. Train a model (Phase 2) and place checkpoint at ai/models/tgnn_model.pt",
        )
    try:
        logger.info("predict request features_keys=%s has_graph=%s", list((req.features or {}).keys())[:12], bool(req.graph_snapshot))
        result = inference_service.predict(req.features, req.graph_snapshot)
        logger.info(
            "predict result attack=%s stage=%s threat=%s confidence=%.4f",
            result.get("attack_type"),
            result.get("attack_stage"),
            result.get("threat_level"),
            float(result.get("confidence") or 0),
        )
        return result
    except Exception as e:
        logger.exception("predict failed")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/predict/batch")
def predict_batch(req: BatchPredictRequest):
    if not inference_service.is_loaded:
        raise HTTPException(
            status_code=503,
            detail="TGNN model not loaded. Train a model (Phase 2) and place checkpoint at ai/models/tgnn_model.pt",
        )
    if not req.records:
        raise HTTPException(status_code=400, detail="records must be a non-empty list")
    try:
        return {"predictions": inference_service.predict_batch(req.records)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/explain")
def explain(req: ExplainRequest):
    try:
        return explainability_service.explain(req.node_id, req.graph_snapshot)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/train")
def start_training(req: TrainRequest):
    try:
        result = training_service.start_training(
            run_id=req.run_id,
            dataset_id=req.dataset_id,
            architecture=req.architecture,
            hyperparameters=req.hyperparameters,
            epochs=req.epochs,
            graph_strategy=req.graph_strategy,
            graph_params=req.graph_params,
            feature_set=req.feature_set,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/train/{run_id}")
def get_training_status(run_id: str):
    status = training_service.get_status(run_id)
    if not status:
        raise HTTPException(status_code=404, detail="Training run not found")
    return status


@app.get("/api/v1/metrics")
def get_metrics(model_id: str | None = None):
    return training_service.get_metrics(model_id)


@app.get("/api/v1/evaluation")
def get_evaluation(model_id: str | None = None):
    """Full advanced evaluation payload (ROC/PR curves, confusion matrix, per-class)."""
    return training_service.get_metrics(model_id)


@app.post("/api/v1/datasets/upload")
async def upload_dataset(
    file: UploadFile = File(...),
    source: str = Form("upload"),
    name: str = Form(""),
):
    try:
        file_id = str(uuid.uuid4())
        ext = Path(file.filename or "data.csv").suffix
        dest = UPLOAD_DIR / f"{file_id}{ext}"

        content = await file.read()
        dest.write_bytes(content)

        record_count = 0
        if ext.lower() == ".csv":
            df = pd.read_csv(dest, nrows=100000)
            record_count = len(df)
        elif ext.lower() in (".pcap", ".pcapng"):
            record_count = len(content) // 100

        return {
            "file_path": str(dest),
            "filename": file.filename,
            "source": source,
            "name": name or file.filename,
            "record_count": record_count,
            "file_type": ext.lstrip("."),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/graph/build")
def build_graph(req: GraphBuildRequest):
    try:
        from app.data.loaders import load_dataset
        df = load_dataset(req.dataset_id, max_rows=10000)
        params = dict(req.graph_params or {})
        params.setdefault("window_size", req.window_seconds)
        if req.feature_set is not None:
            params["feature_set"] = req.feature_set
        cfg = GraphConfig.from_dict(req.graph_strategy, params)
        snapshot = build_one_snapshot(df, cfg)
        return {
            "node_count": snapshot["node_count"],
            "edge_count": snapshot["edge_count"],
            "graph_strategy": cfg.strategy,
            "graph_params": cfg.to_metadata(),
            "feature_set": cfg.feature_set,
            "snapshot": snapshot,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/graph/strategies")
def graph_strategies():
    """Available graph construction strategies (for the frontend dropdown)."""
    return {"strategies": GRAPH_STRATEGIES}


@app.get("/api/v1/config")
def get_studio_config():
    """Return the persisted Model Studio configuration (auto-loaded by the UI)."""
    return load_config()


@app.post("/api/v1/config")
def post_studio_config(req: StudioConfigRequest):
    try:
        return save_config(req.config)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/predict/from-dataset")
def predict_from_dataset(req: PredictDatasetRequest):
    """Build a temporal graph from a dataset and run TGNN inference server-side."""
    if not inference_service.is_loaded:
        raise HTTPException(
            status_code=503,
            detail="TGNN model not loaded. Train a model (Phase 2) first.",
        )
    try:
        from app.data.loaders import load_dataset

        df = load_dataset(req.dataset_id, max_rows=req.max_rows)
        params = dict(req.graph_params or {})
        params.setdefault("window_size", req.window_seconds)
        if req.feature_set is not None:
            params["feature_set"] = req.feature_set
        elif inference_service.metadata.get("feature_set"):
            params["feature_set"] = inference_service.metadata.get("feature_set")
        cfg = GraphConfig.from_dict(req.graph_strategy, params)
        snapshot = build_one_snapshot(df, cfg)
        prediction = inference_service.predict({}, snapshot)
        return {
            **prediction,
            "graph": {
                "node_count": snapshot.get("node_count", 0),
                "edge_count": snapshot.get("edge_count", 0),
                "attack_type": snapshot.get("attack_type"),
                "label": snapshot.get("label"),
                "graph_strategy": cfg.strategy,
                "graph_params": cfg.to_metadata(),
                "feature_set": cfg.feature_set,
            },
            "dataset_id": req.dataset_id,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ======================================================================
# LIVE authorized local capture → existing GNN pipeline
# ======================================================================


class LiveStartRequest(BaseModel):
    interface: str
    window_seconds: int = 5


@app.get("/api/v1/live/interfaces")
def live_interfaces():
    """List local NICs available for authorized capture."""
    from app.live import live_manager

    return {"interfaces": live_manager.list_interfaces()}


@app.post("/api/v1/live/start")
def live_start(req: LiveStartRequest):
    """Start authorized local packet capture (does not auto-start on boot)."""
    from app.live import live_manager

    try:
        return live_manager.start(req.interface, req.window_seconds)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/live/stop")
def live_stop():
    from app.live import live_manager

    try:
        return live_manager.stop()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/live/status")
def live_status():
    from app.live import live_manager

    return live_manager.status()


@app.get("/api/v1/live/history")
def live_history():
    """Recent live windows (capped) for timeline visualization."""
    from app.live import live_manager

    return {"windows": live_manager.history(), "count": len(live_manager.history())}


@app.post("/api/v1/risk/compute")
def compute_risk(req: RiskComputeRequest):
    try:
        return risk_engine.compute(req.entity_type, req.entity_id, req.graph_snapshot)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ======================================================================
# Phase 12 — Continual Learning System
# ======================================================================


class DatasetRegisterRequest(BaseModel):
    name: str | None = None
    dataset_id: str = "cicids2017"
    source: str = "loader"
    max_rows: int = 20000


class DriftRequest(BaseModel):
    name: str | None = None
    dataset_id: str = "cicids2017"
    max_rows: int = 20000


class RetrainRequest(BaseModel):
    dataset_id: str = "cicids2017"
    architecture: str = "gat"
    hyperparameters: dict[str, Any] = Field(default_factory=dict)
    epochs: int = 30
    graph_strategy: str | None = None
    graph_params: dict[str, Any] = Field(default_factory=dict)
    mode: str = "full"
    use_replay: bool = False
    replay_ratio: float = 0.15
    include_review_samples: bool = False


class CandidateRequest(BaseModel):
    candidate_id: str


class RelabelRequest(BaseModel):
    label: str


def _persist_drift(name: str, report: dict[str, Any]) -> None:
    try:
        stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        path = drift_dir() / f"{name}_{stamp}.json"
        path.write_text(
            json.dumps({"name": name, "computed_at": datetime.utcnow().isoformat(), **report}, default=str),
            encoding="utf-8",
        )
    except OSError:
        pass


@app.get("/api/v1/datasets")
def list_datasets(name: str | None = None):
    """Registered dataset versions (dataset_v1, dataset_v2, ...)."""
    return dataset_manager.list_versions(name)


@app.get("/api/v1/datasets/history")
def dataset_history():
    return {"history": dataset_manager.history()}


@app.post("/api/v1/datasets")
def register_dataset(req: DatasetRegisterRequest):
    """Collect + version a dataset (quality check → version → drift)."""
    try:
        from app.data.loaders import load_dataset

        df = load_dataset(req.dataset_id, max_rows=req.max_rows)
        name = req.name or req.dataset_id
        result = continual.ingest_dataframe(name, df, source=req.source)
        if result.get("drift"):
            _persist_drift(name, result["drift"])
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/datasets/upload-version")
async def upload_dataset_version(
    file: UploadFile = File(...),
    name: str = Form(""),
    source: str = Form("upload"),
):
    """Collect + version an uploaded CSV (quality-screened before storing)."""
    try:
        content = await file.read()
        tmp = UPLOAD_DIR / f"{uuid.uuid4()}.csv"
        tmp.write_bytes(content)
        df = pd.read_csv(tmp, nrows=200000)
        ds_name = name or (file.filename or "uploaded_dataset")
        result = continual.ingest_dataframe(ds_name, df, source=source)
        if result.get("drift"):
            _persist_drift(ds_name, result["drift"])
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/drift")
def get_drift():
    """Recent drift reports (most recent first)."""
    reports_out: list[dict[str, Any]] = []
    try:
        for p in sorted(drift_dir().glob("*.json"), reverse=True)[:50]:
            try:
                reports_out.append(json.loads(p.read_text(encoding="utf-8")))
            except (json.JSONDecodeError, OSError):
                continue
    except OSError:
        pass
    return {"reports": reports_out}


@app.post("/api/v1/drift")
def compute_drift(req: DriftRequest):
    """Compute drift for a dataset's current data vs its registered baseline."""
    try:
        from app.data.loaders import load_dataset

        df = load_dataset(req.dataset_id, max_rows=req.max_rows)
        name = req.name or req.dataset_id
        report = continual.analyze_drift(name, df)
        if report.get("available"):
            _persist_drift(name, report)
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/experiments")
def list_experiments(dataset_id: str | None = None, limit: int = 200):
    return {"experiments": experiment_store.list(limit=limit, dataset_id=dataset_id)}


@app.get("/api/v1/training/history")
def training_history(dataset_id: str | None = None, limit: int = 200):
    """Alias of /experiments (every training run recorded in the audit trail)."""
    return {
        "history": experiment_store.list(limit=limit, dataset_id=dataset_id),
        "accuracy_trend": experiment_store.accuracy_trend(dataset_id),
    }


@app.get("/api/v1/approvals")
def approval_history(limit: int = 100):
    from app.services.experiments import approval_store

    return {"approvals": approval_store.list(limit=limit), "count": min(limit, 100)}


@app.post("/api/v1/retrain")
def retrain(req: RetrainRequest):
    """Train a candidate model (never activated automatically)."""
    try:
        return continual.retrain_candidate(
            dataset_id=req.dataset_id,
            architecture=req.architecture,
            hyperparameters=req.hyperparameters,
            epochs=req.epochs,
            graph_strategy=req.graph_strategy,
            graph_params=req.graph_params,
            mode=req.mode,
            use_replay=req.use_replay,
            replay_ratio=req.replay_ratio,
            include_review_samples=req.include_review_samples,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/compare")
def compare_models(req: CandidateRequest):
    try:
        return continual.compare_with_active(req.candidate_id)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/rollback")
def rollback_model():
    """Restore the previous active checkpoint (one-step rollback)."""
    try:
        return continual.rollback_active()
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/rollback/info")
def rollback_info():
    from app.services.registry import model_registry

    return model_registry.rollback_info()


@app.get("/api/v1/replay/stats")
def replay_stats():
    return continual.replay_stats()


@app.post("/api/v1/approve-model")
def approve_model(req: CandidateRequest):
    try:
        return continual.approve_candidate(req.candidate_id)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/review")
def list_review(status: str | None = None, limit: int = 200):
    return {"samples": review_queue.list(status=status, limit=limit), "stats": review_queue.stats()}


@app.get("/api/v1/review/uncertain")
def uncertain_review(limit: int = 20):
    """Active learning: most uncertain pending samples for human labelling."""
    return {"samples": review_queue.select_uncertain(limit=limit)}


@app.post("/api/v1/review/{sample_id}/relabel")
def relabel_review(sample_id: str, req: RelabelRequest):
    try:
        return review_queue.relabel(sample_id, req.label)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/v1/review/{sample_id}/approve")
def approve_review(sample_id: str):
    try:
        from app.services.replay_buffer import replay_buffer

        updated = review_queue.approve(sample_id)
        replay_buffer.add_from_review_sample(updated)
        return updated
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/api/v1/knowledge-base")
def get_knowledge_base():
    return knowledge_base.summary()


@app.get("/api/v1/reports")
def get_report(model_id: str | None = None, format: str = "json"):
    """Evaluation report as json / csv / html (html is print-to-PDF ready)."""
    try:
        report = reports.build_report(model_id)
        content, media_type = reports.render(report, format)
        if format.lower() == "json":
            return report
        return Response(content=content, media_type=media_type)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class SOCRequest(BaseModel):
    attack_type: str
    attack_stage: str | None = None
    confidence: float = 0.0
    threat_level: str | None = None
    risk_score: float = 0.0
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    source_ip: str | None = None
    target_ip: str | None = None
    protocol: str | None = None
    port: int | str | None = None


@app.post("/api/v1/soc/response")
def soc_response(req: SOCRequest):
    """Generate a SOC response bundle (MITRE, kill-chain, Sigma/YARA/Suricata/
    Snort rules, firewall/isolation commands, response playbook) for an
    attack type. Reuses the same engine attached to every live prediction."""
    from app.services.soc_response import soc_engine
    from app.services.inference import MITRE_MAP, THREAT_LEVELS

    tactic = req.mitre_tactic
    technique = req.mitre_technique
    if tactic is None or technique is None:
        default_tactic, default_technique = MITRE_MAP.get(req.attack_type, ("Unknown", "T0000"))
        tactic = tactic or default_tactic
        technique = technique or default_technique
    threat = req.threat_level or THREAT_LEVELS.get(req.attack_type, "medium")

    try:
        return soc_engine.build(
            attack_type=req.attack_type,
            attack_stage=req.attack_stage,
            confidence=req.confidence,
            threat_level=threat,
            risk_score=req.risk_score,
            mitre_tactic=tactic,
            mitre_technique=technique,
            source_ip=req.source_ip,
            target_ip=req.target_ip,
            protocol=req.protocol,
            port=req.port,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
