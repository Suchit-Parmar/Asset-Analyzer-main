# FINAL_REPORT.md

## Title
AI-Driven Cyber Attack Prediction using Temporal Graph Neural Networks (TGNN)

## Abstract
This project implements an end-to-end Security Operations Center prototype that predicts cyber attack types and kill-chain stages using a Temporal Graph Neural Network. Network flows from benchmark datasets are converted into temporal graphs, a TGNN is trained and checkpointed, FastAPI serves inference, Express authenticates operators and persists predictions/alerts in PostgreSQL, and a React dashboard presents live SOC views with WebSocket updates.

## 1. Introduction
Intrusion detection systems often classify isolated events. Advanced attackers move laterally across hosts over time. Graph neural networks can model communication structure; temporal extensions capture progression across windows. This work builds a practical pipeline from dataset to operator UI.

## 2. Objectives
1. Integrate real datasets (CICIDS2017 and related loaders).
2. Train a TGNN and save a production checkpoint.
3. Expose inference APIs and persist results.
4. Build authenticated dashboards for predictions, alerts, topology, risk, and model status.
5. Polish reliability, remove mock data, and document the system.

## 3. Literature / background (brief)
- Graph Neural Networks for relational learning
- Temporal graphs for evolving networks
- MITRE ATT&CK for SOC vocabulary
- Modern full-stack security tooling (JWT, RBAC, WS)

## 4. System design
See PROJECT_ARCHITECTURE.md. Key split: Python for ML, Node for product API/UI integration.

## 5. Implementation phases
- **Phase 1:** Dataset integration & graph building
- **Phase 2:** TGNN training → `ai/models/tgnn_model.pt`
- **Phase 3:** FastAPI inference + Express persistence
- **Phase 4:** Frontend wired to live APIs + WebSocket
- **Phase 5:** Bug fixes, mock removal, UX polish, documentation pack

## 6. Model
Architecture family: GAT (default), with GraphSAGE/GCN options. Multi-head outputs for attack classification, stage classification, next-stage prediction, risk regression, and compromise classification.

## 7. Results
Training produces measurable accuracy/precision/recall/F1 on held-out temporal snapshots. Inference returns confidence scores stored in PostgreSQL. The UI displays prediction history, alerts (with MITRE when applicable), topology, risk cards, and model metadata without fabricated dashboard metrics.

## 8. Testing
Covered by TEST_CASES.md: auth, predict paths, persistence, frontend empty/error states, and resilience when AI is offline.

## 9. Conclusion
The project demonstrates a complete academic-to-prototype path for TGNN-based attack prediction with production-minded API and SOC UI integration.

## 10. Future work
Streaming ingestion, stronger class-balanced training, GPU deployment, richer explainability visualizations, and SIEM connectors.
