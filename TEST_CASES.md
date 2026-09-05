# TEST_CASES.md

## Auth

| ID | Case | Steps | Expected |
|----|------|-------|----------|
| A1 | Valid login | POST `/api/auth/login` with seeded admin | 200 + accessToken |
| A2 | Invalid password | Wrong password | 401 |
| A3 | Protected without token | GET `/api/predictions` | 401 |
| A4 | Me endpoint | GET `/api/auth/me` with token | User + role |

## Inference

| ID | Case | Steps | Expected |
|----|------|-------|----------|
| I1 | Feature predict | POST `/api/predict` with features | Stored prediction id |
| I2 | Batch predict | POST `/api/predict/batch` with 2 records | count=2 |
| I3 | Dataset predict | POST `/api/predict/dataset` | Prediction + graph summary |
| I4 | Model missing | Rename checkpoint, call predict | 503/500 with clear error |
| I5 | FastAPI health | GET `:8000/health` | model_loaded true |

## Persistence

| ID | Case | Steps | Expected |
|----|------|-------|----------|
| P1 | Predictions list | GET `/api/predictions` | Includes latest id |
| P2 | Alert on non-low | Predict elevated threat | Alert row + predictionId |
| P3 | No alert on low | Normal/low threat | Prediction only |

## Frontend

| ID | Case | Steps | Expected |
|----|------|-------|----------|
| F1 | Dashboard load | Login → `/` | Metrics load, no crash |
| F2 | Empty predictions | Fresh DB | Empty state message |
| F3 | Run Dataset Predict | Click button | Toast + history update |
| F4 | WS reconnect | Stop/start Express briefly | Status reconnects |
| F5 | Topology empty | No nodes | AWAITING TOPOLOGY (no fake nodes) |
| F6 | Evaluation metrics | Open Evaluation | Real checkpoint metrics only |

## Negative / resilience

| ID | Case | Expected |
|----|------|----------|
| N1 | AI service stopped | Predict fails gracefully; UI error/toast |
| N2 | Oversized graph body | Prefer `/predict/dataset` path |
| N3 | Expired JWT | Refresh or re-login |

## Manual verification commands

```bash
curl http://127.0.0.1:8000/health
curl -X POST http://127.0.0.1:5000/api/auth/login -H "Content-Type: application/json" -d "{\"email\":\"admin@gnn-ids.local\",\"password\":\"Admin@123456\"}"
```
