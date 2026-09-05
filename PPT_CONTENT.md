# PPT_CONTENT.md — Slide outline (12–15 slides)

## Slide 1 — Title
AI-Driven Cyber Attack Prediction using Temporal Graph Neural Networks (TGNN)  
7th Semester Project · Asset Analyzer

## Slide 2 — Problem
- Modern attacks are multi-stage and multi-host
- Signature IDS miss novel patterns
- Need predictive, explainable SOC tooling

## Slide 3 — Objectives
- Train TGNN on real datasets
- Serve live inference
- Persist predictions/alerts
- Visualize SOC dashboards with live updates

## Slide 4 — Architecture
React → Express (JWT) → PostgreSQL  
  ↘ FastAPI + PyTorch TGNN checkpoint

## Slide 5 — Dataset & Graph Construction
- CICIDS2017 flows
- Temporal windows → nodes (IPs) + edges (connections)
- Feature vectors per node

## Slide 6 — TGNN Model
- GAT / GraphSAGE / GCN options
- Temporal attention + classifiers
- Outputs: attack type, stage, next stage, risk

## Slide 7 — Training (Phase 2)
- Checkpoint `tgnn_model.pt`
- Metrics: accuracy, precision, recall, F1

## Slide 8 — Inference Service (Phase 3)
- FastAPI `/api/v1/predict*`
- Express persistence + alerts + MITRE

## Slide 9 — Frontend SOC (Phase 4)
- Dashboard, alerts, topology, risk, model info
- WebSocket live stream
- JWT login

## Slide 10 — Demo screenshots placeholders
- Login
- Dashboard with prediction history
- Alert Center MITRE
- Topology canvas

## Slide 11 — Security
JWT, RBAC, bcrypt, optional TOTP, audit logs

## Slide 12 — Results & Observations
- End-to-end pipeline works on real checkpoint
- Alerts generated for elevated threats
- Live UI without mock metrics

## Slide 13 — Limitations & Future work
- Improve model accuracy / class balance
- Richer explainability UI
- Streaming PCAP ingestion

## Slide 14 — Conclusion
Delivered a full-stack TGNN SOC prototype from data → model → API → dashboard.

## Slide 15 — Q&A
Thank you
