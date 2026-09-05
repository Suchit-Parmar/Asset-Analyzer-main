# VIVA_QUESTIONS.md

## Conceptual

**Q1. What is a Temporal Graph Neural Network?**  
A GNN that models entities as graph nodes/edges and incorporates time (windows/sequences) so attack progression can be learned across snapshots.

**Q2. Why graphs for intrusion detection?**  
Network traffic is relational (hosts communicate). Graphs capture lateral movement and multi-host patterns better than isolated flow vectors alone.

**Q3. What dataset did you train on?**  
Primarily CICIDS2017 (Phase 2). The platform also supports UNSW-NB15, TON-IoT, NSL-KDD loaders.

**Q4. What does the model predict?**  
Attack type, current attack stage, likely next stage, compromise likelihood, and a risk score — plus explanation metadata (attention/importance).

**Q5. What is MITRE ATT&CK mapping in this project?**  
Predicted attack types are mapped to tactic/technique labels stored on alerts for SOC context.

## System design

**Q6. Why FastAPI and Express together?**  
FastAPI hosts PyTorch inference efficiently; Express handles auth, RBAC, PostgreSQL, and the React API surface.

**Q7. Where is the model stored?**  
`ai/models/tgnn_model.pt` with architecture/hyperparameter metadata in the checkpoint dict.

**Q8. How are live updates delivered?**  
WebSocket `/ws?token=JWT` broadcasts prediction/alert events; React Query invalidates caches.

**Q9. How is security enforced?**  
JWT access/refresh tokens, bcrypt passwords, role permissions, optional TOTP, Helmet, rate limits.

**Q10. What happens if AI is down?**  
Predict endpoints fail with clear errors; previously stored DB rows still render in the UI.

## Implementation

**Q11. How do you avoid mock dashboard data?**  
Pages call real `/api/*` endpoints; unused mock modules were removed in Phase 5; topology has no fake node fallback.

**Q12. What is `/api/predict/dataset`?**  
Server-side path that builds a temporal graph from a dataset and runs TGNN without shipping huge snapshots through the browser.

**Q13. How are alerts created?**  
After inference, if `threat_level` is not `low`/`info`, Express inserts an `alerts` row linked to the prediction.

**Q14. What ORM/schema approach?**  
Drizzle schema in `shared/schema.ts` shared by the Node backend.

**Q15. Limitations?**  
Model accuracy depends on training data/epochs; Python 3.14 NetworkX quirks; topology sync needs AI availability at startup.
