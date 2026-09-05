# Phase 3 Summary — Inference Integration

**Status:** Completed  
**Date:** 11 July 2026  
**Scope:** Connect trained TGNN model to FastAPI, wire Express backend, persist predictions/alerts in PostgreSQL  
**Out of scope:** Frontend changes, Phase 1/2 rework

---

## Objectives

| Requirement | Status |
|-------------|--------|
| Connect trained TGNN checkpoint to FastAPI inference | Done |
| Implement prediction endpoints | Done |
| Connect Express backend with FastAPI inference | Done |
| Store predictions and alerts in PostgreSQL | Done |
| Do not modify frontend | Done |
| Stop after Phase 3 | Done |

---

## Prerequisites (from prior phases)

- Phase 1: Dataset integration complete
- Phase 2: TGNN model trained
- Checkpoint: `ai/models/tgnn_model.pt`
  - Architecture: GAT
  - Hidden dim: 64
  - Node features: 16
  - Dataset: CICIDS2017
  - Trained: 2026-07-10T18:50:02

---

## What Was Implemented

### 1. FastAPI inference service (`ai/app/services/inference.py`)

- Resolves `MODEL_DIR` robustly (env var or `ai/models`)
- Loads checkpoint **metadata** (`architecture`, `hidden_dim`, `node_features`, metrics, labels)
- Rejects inference if no trained checkpoint exists
- Supports feature-vector and graph-snapshot inputs
- Pads/truncates node features to match checkpoint dim
- Returns attack type, stage, next stage, threat level, confidence, risk, MITRE mapping, explanation

### 2. FastAPI endpoints (`ai/app/main.py`)

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | Service + model load status |
| GET | `/api/v1/model/info` | Checkpoint metadata & metrics |
| POST | `/api/v1/model/reload` | Reload checkpoint from disk |
| POST | `/api/v1/predict` | Single prediction |
| POST | `/api/v1/predict/batch` | Batch prediction |
| POST | `/api/v1/predict/from-dataset` | Build graph from dataset + predict server-side |

Startup logs confirm model load path and architecture.

### 3. Express ↔ FastAPI client (`server/ai-client.ts`)

- `health()`, `modelInfo()`, `reloadModel()`
- `predict()`, `predictBatch()`, `predictFromDataset()`
- Uses `AI_SERVICE_URL` (default `http://localhost:8000`)

### 4. Express API routes (`server/routes/api.routes.ts`)

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/predict` | Call AI, store prediction (+ alert if needed) |
| POST | `/api/predict/batch` | Batch predict + persist each result |
| POST | `/api/predict/dataset` | Dataset-based predict + persist |
| GET | `/api/model/info` | Proxy model info |
| POST | `/api/model/reload` | Proxy model reload |
| GET | `/api/predictions` | List stored predictions |
| GET | `/api/alerts` | List stored alerts |
| GET | `/api/health` | App + AI health |

Persistence helpers:

- Normalize attack stages / threat levels for PostgreSQL enums
- Register active model in `ml_models` (`TGNN Production`) if missing
- Insert into `predictions`
- Insert into `alerts` when `threat_level` is not `low` or `info`
- Broadcast WebSocket events + Redis publish for predictions/alerts
- Audit log on predict

### 5. Supporting fixes

- `server/index.ts`: JSON body limit raised to **50mb** (large graph snapshots)
- `ai/app/services/risk_engine.py`: Soft-fail NetworkX import (Python 3.14 compatibility)
- `python-multipart` installed for FastAPI form uploads
- `server/sync-network.ts`: Default dataset set to `cicids2017` (matches Phase 2 training)

---

## PostgreSQL Storage

### Tables used

- **`predictions`** — attack type/stage, confidence, risk, explanation, raw features, optional `modelId`
- **`alerts`** — severity, MITRE fields, IPs, linked `predictionId` (non-low threats only)
- **`ml_models`** — active production model record pointing at `ai/models/tgnn_model.pt`

### Alert policy

Alerts are created only when predicted `threat_level` ∈ `{critical, high, medium}`.  
`Normal` / `low` predictions are stored without alerts.

---

## Verification Results

| Test | Result |
|------|--------|
| FastAPI `/health` | `model_loaded: true`, arch=`gat`, dataset=`cicids2017` |
| FastAPI `/api/v1/predict` | Returns attack/stage/confidence/risk |
| Express login + `/api/predict` | Prediction stored (`stored: true`, UUID `id`) |
| Express `/api/predict/batch` | 2 predictions persisted |
| Express `/api/predict/dataset` | Graph built (e.g. ~3217 nodes) + prediction stored |
| Express `/api/predictions` | Lists persisted rows |
| Express `/api/health` | Reports AI healthy + model loaded |
| Active model registry | `TGNN Production` created with `isActive: true` |

---

## How to Run Phase 3

### Terminal 1 — AI service

```bash
cd ai
set MODEL_DIR=..\ai\models
set DATASET_ROOT=..\DataSet
py -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### Terminal 2 — Express backend

```bash
npm run dev
```

### Example calls

```bash
# Health
curl http://127.0.0.1:8000/health

# Login (Express)
curl -X POST http://127.0.0.1:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"admin@gnn-ids.local\",\"password\":\"Admin@123456\"}"

# Predict (use access token from login)
curl -X POST http://127.0.0.1:5000/api/predict \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d "{\"features\":{\"duration\":2.5,\"src_bytes\":5000,\"dst_bytes\":1200,\"protocol\":\"tcp\",\"src_ip\":\"192.168.1.50\",\"dst_ip\":\"10.0.0.5\"}}"

# Predict from dataset
curl -X POST http://127.0.0.1:5000/api/predict/dataset \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d "{\"datasetId\":\"cicids2017\",\"windowSeconds\":30,\"maxRows\":3000}"
```

---

## Files Changed / Added

| File | Change |
|------|--------|
| `ai/app/services/inference.py` | Checkpoint-aware inference service |
| `ai/app/main.py` | Predict/model endpoints + startup load |
| `ai/app/services/risk_engine.py` | NetworkX import soft-fail |
| `server/ai-client.ts` | Inference client methods |
| `server/routes/api.routes.ts` | Predict persistence + model routes |
| `server/index.ts` | 50mb JSON body limit |
| `server/sync-network.ts` | Default dataset → cicids2017 |
| `summary.md` | This Phase 3 summary |

**Frontend:** not modified.

---

## Architecture (Phase 3 data flow)

```
Client / API caller
        │
        ▼
 Express (port 5000)
  - JWT auth / RBAC
  - POST /api/predict*
  - Persist predictions + alerts
        │  HTTP
        ▼
 FastAPI AI (port 8000)
  - Load ai/models/tgnn_model.pt
  - TGNN forward pass
  - Return attack / stage / risk
        │
        ▼
 PostgreSQL
  - predictions
  - alerts
  - ml_models
```

---

## Notes

- Feature-only inputs currently often classify as `Normal` / `low` with the Phase 2 checkpoint; alerts appear when the model returns medium+ threat levels.
- Large graph snapshots should prefer `/api/predict/dataset` (server-side graph build) to avoid shipping huge payloads through Express.
- Phase 3 ends here; no Phase 4 work was started.
