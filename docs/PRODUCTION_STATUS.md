# Production Platform Status

Last updated: July 2026. This document tracks the research-to-production roadmap for the AI-Driven Cyber Attack Prediction Platform (TGNN / GNN-IDS).

## Architecture (live stack)

```
Browser (React SOC UI :5173 dev / :5000 prod)
    ↕ JWT + WebSocket (/ws)
Express API (server/ :5000)
    ↕ HTTP proxy
FastAPI AI service (ai/ :8000)
    ↕ checkpoints
ai/models/tgnn_model.pt + per-dataset *.pt
    ↕ Drizzle ORM
PostgreSQL (predictions, alerts, audit, topology)
```

## Phase completion matrix

| Phase | Feature | Status |
|-------|---------|--------|
| 1 | Metrics, graph strategies, batching | Done |
| 2 | Model registry | Done |
| 3 | Model Studio feature toggles | Done |
| 4 | Training engine (AMP, early stop, ETA) | Done |
| 5 | Advanced evaluation (ROC/PR, export) | Done |
| 6 | Explainability (IG, SHAP, reasoning tree, heatmap) | Done |
| 7 | Network Scanner enhancements | Done |
| 8 | SOC response engine | Done |
| 9 | Research Dashboard (approvals, charts) | Done |
| 10–11 | Replay buffer, rollback, review→train | Done |
| 12 | Continual learning + real-time WS | Done |
| 13 | Admin monitoring + system logs | Done |
| 14 | Report export (JSON/CSV/HTML/PDF print) | Done |
| 15 | Lazy routes, chart fullscreen | Done |
| 16–17 | Dead code removal, DB indexes | Done |
| 18 | This document + existing architecture docs | Done |

## Continual learning safety rules

1. **Candidates never auto-activate** — `activate=False` on all retrain paths.
2. **Compare before approve** — `POST /api/v1/compare` then human `approve-model`.
3. **Rollback** — `previous_active.pt` snapshot before every activation; `POST /api/v1/rollback`.
4. **Replay buffer** — optional `use_replay` + `include_review_samples` on retrain to reduce catastrophic forgetting.
5. **Incremental fine-tune** — 4× lower learning rate, max 25 epochs.

## Key API endpoints

| Endpoint | Purpose |
|----------|---------|
| `POST /api/v1/retrain` | Train candidate (optional replay flags) |
| `POST /api/v1/compare` | Champion vs challenger metrics |
| `POST /api/v1/approve-model` | Promote candidate (backs up previous active) |
| `POST /api/v1/rollback` | Restore previous active checkpoint |
| `GET /api/v1/approvals` | Approval audit trail |
| `GET /api/v1/replay/stats` | Replay buffer statistics |
| `POST /api/v1/soc/response` | MITRE / kill-chain / playbook |
| `GET /api/v1/admin/system` | CPU/RAM/disk/GPU metrics |

## On-disk artefacts

| Path | Contents |
|------|----------|
| `ai/models/` | Checkpoints + registry sidecars |
| `ai/models/previous_active.pt` | Last active model before promotion |
| `ai/data/replay/` | Experience replay buffer JSONL |
| `ai/data/review/` | Active-learning review queue |
| `ai/experiments/` | Experiment + approval JSONL logs |

## Related documentation

- [PROJECT_ARCHITECTURE.md](../PROJECT_ARCHITECTURE.md) — system overview
- [docs/continual-learning.md](./continual-learning.md) — CL workflow detail
- [docs/graph-strategies.md](./graph-strategies.md) — graph construction
- [API_DOCUMENTATION.md](../API_DOCUMENTATION.md) — REST reference
- [DATABASE_SCHEMA.md](../DATABASE_SCHEMA.md) — PostgreSQL tables

## Operator checklist

1. `pip install -r ai/requirements.txt` (includes `psutil`)
2. `npm run db:push` after schema index updates
3. Train initial model via Model Studio → Experiment page
4. Use Research Dashboard for drift → retrain → compare → approve
5. Enable replay/review checkboxes when incrementally updating models
