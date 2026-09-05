# DEMO_SCRIPT.md — 8–10 minute live demo

## Setup before demo

1. AI service running on `:8000` with `model_loaded: true`
2. `npm run dev` on `:5000`
3. Browser ready at http://localhost:5000

## Script

### 1. Login (30s)
- Open login page
- Sign in as `admin@gnn-ids.local` / `Admin@123456`
- Point out JWT-backed auth (not localStorage-only)

### 2. Dashboard overview (90s)
- Show AI model card (architecture, dataset, trained time)
- Show WebSocket status = Connected
- Show metric cards: nodes, threat posture, confidence, open alerts
- Show risk score cards

### 3. Run live inference (90s)
- Click **Run Dataset Predict**
- Wait for toast success
- Show new row in **Prediction History** with confidence %
- If threat ≥ medium, show alert + MITRE mapping in alert stream

### 4. Topology & timeline (60s)
- Show network topology canvas (live nodes/edges)
- Show attack timeline chart updating with alerts/risk/confidence

### 5. Alert Center (45s)
- Navigate to Alerts
- Show severity counts and MITRE tactic/technique
- Change an alert status (investigating → resolved)

### 6. Attack Intelligence (45s)
- Show stage journey probabilities
- Show recent prediction confidence list
- Show MITRE mapping panel

### 7. Risk & Admin (60s)
- Risk Assessment: risk cards + node matrix
- Admin: model info, reload checkpoint button, health badges

### 8. Close (30s)
- Recap: Dataset → TGNN → FastAPI → Express/Postgres → React/WS
- Mention docs: README, API_DOCUMENTATION, FINAL_REPORT

## Fallback if AI is down
- Show `/health` failure honestly
- Still show previously stored predictions/alerts from PostgreSQL
- Restart uvicorn and re-run predict
