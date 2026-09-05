# API_DOCUMENTATION.md

Base URLs:

- Express: `http://localhost:5000`
- FastAPI: `http://localhost:8000`

Unless noted, Express `/api/*` routes require:

```http
Authorization: Bearer <accessToken>
```

---

## Auth (Express)

### POST `/api/auth/login`

```json
{ "email": "admin@gnn-ids.local", "password": "Admin@123456" }
```

Response: `{ accessToken, refreshToken, user }`

### POST `/api/auth/register`

```json
{ "name": "Analyst", "email": "a@x.com", "password": "password123" }
```

### POST `/api/auth/refresh`

```json
{ "refreshToken": "..." }
```

### GET `/api/auth/me`

Returns current user + permissions.

---

## Inference (Express → FastAPI)

### POST `/api/predict`

```json
{
  "features": {
    "duration": 2.5,
    "src_bytes": 5000,
    "dst_bytes": 1200,
    "protocol": "tcp",
    "src_ip": "192.168.1.10",
    "dst_ip": "10.0.0.5"
  }
}
```

Persists prediction; creates alert if threat ≠ low/info.

### POST `/api/predict/batch`

```json
{ "records": [ { "duration": 1, "src_bytes": 100 }, { "duration": 10, "src_bytes": 90000 } ] }
```

### POST `/api/predict/dataset`

```json
{ "datasetId": "cicids2017", "windowSeconds": 30, "maxRows": 3000 }
```

Builds temporal graph server-side and runs TGNN.

---

## Reads (Express)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/predictions?limit=50` | Prediction history |
| GET | `/api/alerts` | Alerts (`severity`, `status`, `limit`) |
| PATCH | `/api/alerts/:id` | Update status |
| GET | `/api/dashboard/metrics` | SOC summary cards |
| GET | `/api/network/topology` | Graph for visualization |
| GET | `/api/network/nodes` | Network nodes |
| GET | `/api/network/edges` | Network edges |
| GET | `/api/risk/scores` | Risk score rows |
| GET | `/api/attack-stage` | 24h stage aggregation |
| GET | `/api/model/info` | Checkpoint metadata |
| POST | `/api/model/reload` | Reload TGNN weights |
| GET | `/api/metrics` | Training metrics from checkpoint |
| GET | `/api/health` | Express + AI health |
| GET | `/api/training/runs` | Training run list |
| POST | `/api/training/start` | Start training job |
| GET | `/api/datasets` | Dataset registry |

---

## FastAPI (direct)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Model load status |
| GET | `/api/v1/model/info` | Checkpoint info |
| POST | `/api/v1/model/reload` | Reload checkpoint |
| POST | `/api/v1/predict` | Single inference |
| POST | `/api/v1/predict/batch` | Batch inference |
| POST | `/api/v1/predict/from-dataset` | Dataset → graph → predict |
| POST | `/api/v1/train` | Start training |
| POST | `/api/v1/graph/build` | Build temporal graph |

---

## WebSocket

```
ws://localhost:5000/ws?token=<accessToken>
```

Event types: `alert`, `prediction`, `graph_update`, `risk_update`, `training_progress`, `network_topology`, `system_health`.

Example payload:

```json
{
  "type": "prediction",
  "payload": { "id": "...", "attackType": "DoS", "confidence": 0.91 },
  "timestamp": "2026-07-10T19:00:00.000Z"
}
```
