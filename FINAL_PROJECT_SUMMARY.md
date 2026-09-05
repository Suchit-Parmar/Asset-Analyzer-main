# FINAL_PROJECT_SUMMARY.md

## Project
**AI-Driven Cyber Attack Prediction using Temporal Graph Neural Networks (TGNN)**  
Full-stack SOC prototype: dataset → TGNN → FastAPI → Express/PostgreSQL → React + WebSocket.

## Honest ML claims (verified)

| Claim | Status |
|-------|--------|
| Current-window **attack detection** via GNN (`x` + `edge_index`) | Supported |
| Graph message passing (GAT/SAGE/GCN) | Supported |
| **Label leakage** via attack→`failed_logins` features | **Fixed** — traffic-only auth-port short-flow bursts |
| Genuine **next-window (t→t+1)** stage training + separate metrics | Implemented; candidate `cicids2017_verified.pt` |
| Active `tgnn_model.pt` next-window head | Legacy — API uses `heuristic_stage_transition` until activated |
| Fabricated accuracy / fake predictions | Not used |

## Phase completion

| Phase | Focus | Status |
|-------|-------|--------|
| 1–5 | Dataset, train, infer, UI, docs | Completed earlier |
| ML audit | Leakage fix + detection vs next-window | Completed |

## How to run (short)

```bash
cd ai
set MODEL_DIR=..\ai\models
set DATASET_ROOT=..\DataSet
py -m uvicorn app.main:app --host 127.0.0.1 --port 8001

set AI_SERVICE_URL=http://127.0.0.1:8001
npm run dev
```

Login: `admin@gnn-ids.local` / `Admin@123456`

## Key artifacts

| Artifact | Path |
|----------|------|
| Active checkpoint | `ai/models/tgnn_model.pt` |
| Verified candidate (next-window trained) | `ai/models/cicids2017_verified.pt` |
| FastAPI | `ai/app/main.py` |
| Graph builder | `ai/app/graph/builder.py` |
| TGNN | `ai/app/models/tgnn.py` |

## Constraints
- UI/UX frozen during ML audit
- No fake metrics; short verification runs use small chronological slices
- Auth / legacy APIs preserved
