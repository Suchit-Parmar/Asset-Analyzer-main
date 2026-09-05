# AI-Driven Cyber Attack Prediction using Temporal Graph Neural Networks (TGNN)

Production-oriented Security Operations Center (SOC) platform that trains a Temporal Graph Neural Network on real network intrusion datasets, serves live inference through FastAPI, persists results in PostgreSQL via Express, and visualizes threats in a React dashboard with WebSocket updates.

## Highlights

- **TGNN inference** on CICIDS2017 (and other supported datasets)
- **FastAPI AI service** with checkpoint loading and prediction APIs
- **Express + JWT + RBAC** backend with PostgreSQL persistence
- **React SOC dashboards** — predictions, alerts, MITRE mapping, topology, risk, model info
- **Live WebSocket** event stream for alerts and predictions

## Architecture (high level)

```
React (Vite)  →  Express API + WS  →  PostgreSQL / Redis
                      ↓
               FastAPI + PyTorch TGNN
                      ↓
               ai/models/tgnn_model.pt
```

## Quick start

See **[INSTALL.md](./INSTALL.md)** for full setup.

```bash
# 1) Environment
cp .env.example .env

# 2) Install Node deps + push schema
npm install
npm run db:push
npm run db:seed

# 3) AI service (Python 3.11+ recommended)
cd ai
pip install -r requirements.txt
set MODEL_DIR=..\ai\models
set DATASET_ROOT=..\DataSet
py -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# 4) Express + UI (new terminal)
npm run dev
```

Open http://localhost:5000  
Login: `admin@gnn-ids.local` / `Admin@123456`

## Documentation index

| Document | Purpose |
|----------|---------|
| [INSTALL.md](./INSTALL.md) | Installation steps |
| [API_DOCUMENTATION.md](./API_DOCUMENTATION.md) | REST + WS APIs |
| [PROJECT_ARCHITECTURE.md](./PROJECT_ARCHITECTURE.md) | System design |
| [DATABASE_SCHEMA.md](./DATABASE_SCHEMA.md) | PostgreSQL schema |
| [DEPLOYMENT_GUIDE.md](./DEPLOYMENT_GUIDE.md) | Deploy notes |
| [DEMO_SCRIPT.md](./DEMO_SCRIPT.md) | Live demo walkthrough |
| [TEST_CASES.md](./TEST_CASES.md) | Test checklist |
| [VIVA_QUESTIONS.md](./VIVA_QUESTIONS.md) | Viva Q&A |
| [PPT_CONTENT.md](./PPT_CONTENT.md) | Presentation outline |
| [FINAL_REPORT.md](./FINAL_REPORT.md) | Academic report |
| [FINAL_PROJECT_SUMMARY.md](./FINAL_PROJECT_SUMMARY.md) | End-to-end summary |

## Default ports

| Service | Port |
|---------|------|
| React + Express | 5000 |
| FastAPI AI | 8000 |
| PostgreSQL | 5432 |
| Redis | 6379 (optional) |

## License

Academic / project use — 7th semester Asset Analyzer project.
