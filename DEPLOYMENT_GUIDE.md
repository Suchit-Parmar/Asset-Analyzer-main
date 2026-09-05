# DEPLOYMENT_GUIDE.md

## Environments

| Env | Use |
|-----|-----|
| Development | `npm run dev` + local uvicorn |
| Docker | `docker compose up -d` |
| Production | Build static assets + process managers |

## Production checklist

1. Set strong `JWT_ACCESS_SECRET` / `JWT_REFRESH_SECRET` (≥32 chars).
2. Point `DATABASE_URL` to managed PostgreSQL.
3. Set `AI_SERVICE_URL` to the internal FastAPI host.
4. Mount/persist `ai/models/tgnn_model.pt`.
5. Set `CORS_ORIGIN` to the public UI origin.
6. Enable Redis if using multi-instance WS fan-out (`REDIS_URL`).
7. Run behind HTTPS reverse proxy (nginx config in `nginx/`).

## Build frontend + server bundle

```bash
npm install
npm run build
NODE_ENV=production node dist/index.cjs
```

## AI service (production)

```bash
cd ai
pip install -r requirements.txt
export MODEL_DIR=/app/models
export DATASET_ROOT=/app/DataSet
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1
```

Use 1 worker unless model loading is carefully shared (PyTorch models are memory-heavy).

## Docker Compose

```bash
docker compose up -d --build
```

Typical services: app, ai, postgres, redis, nginx.

## Health probes

- Express: `GET /api/health` (authenticated in current build)
- FastAPI: `GET /health` (public)

## Scaling notes

- Scale Express horizontally with sticky sessions or Redis pub/sub for WS.
- Keep AI service vertically scaled (GPU optional).
- Do not place the React app on a different origin without updating CORS and `VITE_API_URL`.

## Backup

- PostgreSQL dump daily
- Backup `ai/models/*.pt`
- Backup `.env` secrets offline (never commit)
