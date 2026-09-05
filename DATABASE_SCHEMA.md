# DATABASE_SCHEMA.md

Source of truth: `shared/schema.ts` (Drizzle ORM → PostgreSQL).

## Enums

| Enum | Values |
|------|--------|
| `role` | admin, analyst, viewer, operator |
| `alert_severity` | critical, high, medium, low, info |
| `alert_status` | open, investigating, resolved, false_positive |
| `node_type` | ip_address, host, server, router, switch, iot_device, user |
| `node_status` | online, offline, suspicious, compromised |
| `edge_protocol` | tcp, udp, http, https, ssh, dns, ftp, smtp, mqtt, other |
| `attack_stage` | reconnaissance, scanning, credential_attack, privilege_escalation, lateral_movement, persistence, data_exfiltration, impact, normal |
| `dataset_status` | pending, processing, ready, failed |
| `training_status` | queued, running, completed, failed, cancelled |
| `model_architecture` | gat, tgn, graphsage, gcn, tgat, dysat |

## Core tables

### `users` / `roles` / `sessions`
Authentication and RBAC. Passwords stored as bcrypt hashes. Refresh tokens hashed in `sessions`.

### `datasets`
Uploaded or registered datasets (name, source, path, record counts, status).

### `ml_models`
Registered model artifacts (`filePath`, architecture, metrics JSON, `isActive`).

### `training_runs`
Training job status, epoch progress, losses/accuracies, hyperparameters.

### `network_nodes`
Hosts/IPs with risk score, ports, status, department/subnet metadata.

### `network_edges`
Directed/undirected connections between nodes (protocol, weight, packet counts).

### `attack_graphs`
Stored temporal graph snapshots (`snapshotData` JSONB).

### `predictions`
TGNN outputs: attack type/stage, next stage, threat level, probability, confidence, risk score, explanation JSON, raw features.

### `alerts`
SOC alerts linked to `predictionId`, with MITRE tactic/technique, IPs, severity, status.

### `risk_scores`
Entity-level risk breakdown (node/subnet/department/org/propagation/business impact).

### `reports` / `notifications` / `audit_logs`
Reporting, user notifications, and security audit trail.

## Relationships (simplified)

```
roles 1──* users 1──* sessions
users 1──* datasets / training_runs / reports
datasets 1──* training_runs / attack_graphs
ml_models 1──* predictions
network_nodes 1──* network_edges (as source/target)
predictions 1──* alerts
```

## Indexes

Common indexes exist on email, status, severity, attack type/stage, timestamps, and foreign keys for dashboard query performance.

## Migrations

```bash
npm run db:push
npm run db:seed
```
