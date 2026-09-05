# PROJECT_ARCHITECTURE.md

## 1. Purpose

Detect and predict cyber attack stages using a Temporal Graph Neural Network (TGNN), then present results in a SOC-style operator console.

## 2. Layered architecture

```
┌─────────────────────────────────────────────┐
│  Presentation — React 19 + Vite + TanStack  │
│  Dashboard, Alerts, Topology, Risk, Admin   │
└─────────────────────┬───────────────────────┘
                      │ REST + WebSocket
┌─────────────────────▼───────────────────────┐
│  Application — Express (JWT, RBAC, audit)   │
│  Persist predictions/alerts, proxy AI calls │
└───────────┬─────────────────────┬───────────┘
            │                     │
   PostgreSQL / Redis      FastAPI AI Service
                                  │
                           PyTorch TGNN
                           tgnn_model.pt
```

## 3. Components

| Component | Tech | Responsibility |
|-----------|------|----------------|
| `client/` | React, Wouter, Recharts | SOC UI |
| `server/` | Express, Drizzle, WS | Auth, API, persistence |
| `shared/schema.ts` | Drizzle ORM | Single schema source |
| `ai/` | FastAPI, PyG, Torch | Train + infer |
| `DataSet/` | CSV benchmarks | CICIDS2017 etc. |

## 4. Data flow (prediction)

1. Operator clicks **Run Dataset Predict** (or API client calls `/api/predict/dataset`).
2. Express authenticates JWT and forwards to FastAPI `/api/v1/predict/from-dataset`.
3. FastAPI loads dataset → builds temporal graph → runs TGNN forward pass.
4. Express stores prediction in `predictions`; if threat ≥ medium, inserts `alerts`.
5. WebSocket broadcasts `prediction` / `alert` events.
6. React Query invalidates caches and UI refreshes.

## 5. Security

- bcrypt password hashes
- JWT access + refresh tokens
- Role-based permissions (`admin`, `analyst`, `viewer`, `operator`)
- Optional TOTP 2FA
- Helmet + rate limiting on Express

## 6. Design constraints (Phases 3–5)

- Do not invent mock SOC metrics in the dashboard
- Checkpoint path: `ai/models/tgnn_model.pt`
- Express is the only frontend-facing API (FastAPI is internal/AI)

## 7. Failure modes

| Failure | Behavior |
|---------|----------|
| AI down | Express health shows AI unavailable; predict returns 500/503 |
| No checkpoint | FastAPI `model_loaded=false`; predict blocked |
| No JWT | 401 on protected routes; WS refuses connection |
| Empty topology | UI shows awaiting topology (no fake nodes) |
