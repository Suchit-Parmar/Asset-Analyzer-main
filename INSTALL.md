# INSTALL.md — Installation Guide

## Prerequisites

- Node.js **20+**
- Python **3.11 or 3.12** recommended (3.14 may have NetworkX issues)
- npm
- Optional: Docker Desktop, Redis, system PostgreSQL

## 1. Clone / open project

```bash
cd "Asset-Analyzer-main"
```

## 2. Environment file

```bash
cp .env.example .env
```

Important variables:

```env
PORT=5000
DATABASE_URL=postgresql://gnn_ids:gnn_ids_secret@localhost:5432/gnn_ids
AI_SERVICE_URL=http://localhost:8000
JWT_ACCESS_SECRET=change-me-access-secret-min-32-chars-long!!
JWT_REFRESH_SECRET=change-me-refresh-secret-min-32-chars-long!!
MODEL_DIR=./ai/models
DATASET_ROOT=./DataSet
```

If PostgreSQL is not installed, the Express app can start an **embedded PostgreSQL** automatically.

## 3. Node dependencies & database

```bash
npm install
npm run db:push
npm run db:seed
```

Seeded admin:

- Email: `admin@gnn-ids.local`
- Password: `Admin@123456`

## 4. Python AI service

```bash
cd ai
pip install -r requirements.txt
```

Ensure checkpoint exists:

```
ai/models/tgnn_model.pt
```

If missing, train (Phase 2):

```bash
cd ..
py ai\train_cicids.py --epochs 20 --max-rows 20000
```

Start FastAPI:

```bash
cd ai
set MODEL_DIR=%CD%\models
set DATASET_ROOT=%CD%\..\DataSet
py -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Verify:

```bash
curl http://127.0.0.1:8000/health
```

Expect `"model_loaded": true`.

## 5. Start application

From repo root:

```bash
npm run dev
```

Open http://localhost:5000 and sign in with the seeded admin.

## 6. Optional Docker

```bash
docker compose up -d
```

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `python-multipart` missing | `pip install python-multipart` |
| AI health degraded | Check `ai/models/tgnn_model.pt` and `MODEL_DIR` |
| 401 on APIs | Login again; JWT required |
| Empty topology | Start AI before/with Express so network sync can run |
| NetworkX import error on Python 3.14 | Use Python 3.11/3.12 for risk endpoints |

## Dataset location

Place CICIDS2017 CSVs under:

```
DataSet/CICIDS2017/
```
