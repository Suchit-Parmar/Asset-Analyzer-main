# Phase 12 — Continual Learning System

This document describes the research-grade continual-learning layer added on top
of the existing TGNN platform. It is **additive and backward compatible**: no
existing API, checkpoint, page or training path was removed or changed in a
breaking way. Everything here is new, opt-in machinery that lets the system keep
improving from newly collected traffic *safely*.

> **Golden rule:** the active model is **never** replaced automatically. New data
> is collected → evaluated → a *candidate* is trained → compared → a report is
> produced → the user approves → and only then is the candidate activated.

---

## 1. Architecture

```
                         ┌───────────────────────────────────────────┐
   New traffic           │              AI service (FastAPI)          │
   (upload / stream /     │                                            │
    folder / labels)      │   dataset_manager ─ data_quality ─ drift   │
        │                 │        │                │                  │
        ▼                 │        ▼                ▼                  │
  ┌───────────┐  Express  │   versions/        drift/ reports         │
  │  React    │◀─proxy───▶│   experiments (JSONL)                     │
  │ Research  │  /api/... │        │                                  │
  │ Dashboard │           │   training(candidate) ─ registry ─ compare │
  └───────────┘           │        │                          │        │
                          │        ▼                          ▼        │
                          │   review_queue           knowledge_base    │
                          └───────────────────────────────────────────┘
```

| Layer | New modules |
| --- | --- |
| Data | `dataset_manager.py`, `data_quality.py`, `drift.py`, `cl_paths.py` |
| Training | `experiments.py`, `continual.py`, candidate mode in `training.py` |
| Evaluation | `model_compare.py`, `reports.py` |
| Learning loop | `review_queue.py`, `knowledge_base.py` |
| Inference | explainability + review capture in `inference.py` |
| API | new `/api/v1/*` routes in `main.py`, proxied by Express `api.routes.ts` |
| UI | `client/src/pages/ResearchDashboard.tsx` (`/research`) |

### On-disk layout

```
ai/data/versions/<name>/index.json
ai/data/versions/<name>/v1/{data.csv, metadata.json}
ai/data/drift/<name>_<ts>.json
ai/data/review/review_queue.jsonl
ai/data/knowledge_base.json
ai/experiments/experiments.jsonl
ai/models/<slug>__candidate_<ts>.pt   # candidate checkpoints (never auto-active)
```

---

## 2. Continual learning flow

```
New Dataset
   ↓  data_quality.analyze()  →  reject if invalid
Quality Check
   ↓  feature validation (expected columns)
Feature Validation
   ↓  drift.compute_baseline()  (bins + label mix)
Graph Construction  (existing graph strategies)
   ↓
Dataset Versioning  (hash de-dup, dataset_v1..vN)
   ↓  drift.detect_drift()  (PSI + label + concept)
Drift Detection     →  recommend retraining only if SIGNIFICANT
   ↓
Candidate Retraining (activate=False, model_slug=…__candidate_…)
   ↓
Evaluation          (70/15/15 test metrics, FPR/FNR)
   ↓  model_compare.compare()
Compare With Active  →  never keep a worse model
   ↓
Generate Report     (JSON / CSV / HTML)
   ↓
Request User Approval
   ↓
Activate only if approved  (registry.activate → inference reload)
```

---

## 3. Dataset versioning

`DatasetManager` (`dataset_manager.py`) creates immutable versions with metadata:
source, date, rows/columns, sha256 content **hash**, classes, attack
distribution, quality report and a baseline distribution snapshot.

* **Duplicate detection** — identical content (same hash) returns the existing
  version instead of creating a new one (anti duplicate-training / poisoning).
* **Rejection** — datasets that fail `data_quality` checks are never versioned.

## 4. Data quality

`data_quality.analyze()` reports duplicate flows, missing values, corrupted
rows, non-finite values, unknown attack labels, feature mismatch and the class
distribution, plus a `passed` verdict and a 0–1 `score`. Empty / almost-entirely
duplicate / mostly-missing / mostly-unknown datasets are rejected.

## 5. Drift detection

`drift.py` compares a baseline vs candidate data:

* **Covariate shift** — Population Stability Index (PSI) per numeric feature
  (`<0.1` none, `0.1–0.25` moderate, `>0.25` significant).
* **Label drift** — total-variation distance between class mixes.
* **Concept drift** — accuracy/confidence degradation supplied by the caller.

Retraining is **recommended only when drift is significant**; it never triggers
training on its own.

## 6. Smart retraining

`continual.retrain_candidate(mode=…)` supports:

| mode | behaviour |
| --- | --- |
| `full` | train from scratch |
| `incremental` / `finetune` | warm-start from the dataset's own checkpoint |
| `transfer` | warm-start from the currently active model |
| `resume` | warm-start from the dataset's checkpoint and continue |

Every run is written to the experiment log; candidates are saved to a distinct
`…__candidate_<ts>.pt` and **never** overwrite `tgnn_model.pt`.

## 7. Automatic model comparison

`model_compare.compare()` builds a side-by-side table (accuracy, precision,
recall, F1, macro-F1, ROC-AUC, macro **FPR/FNR** from the confusion matrix,
training/inference time, graph density, memory) and recommends `promote_candidate`
only if the candidate improves headline F1 without a material accuracy
regression. The recommendation is advisory — activation still requires approval.

## 8. Confidence-based & active learning

Low-confidence / unknown predictions are captured by `review_queue.py` during
inference. Reviewers can relabel and approve samples; `select_uncertain()`
surfaces the most uncertain pending samples first (active learning).

## 9. Explainable AI

Every prediction now includes: confidence, risk, threat level, **top
contributing features** (feature importance), **graph statistics** (nodes, edges,
density, avg degree) and a plain-language **reasoning summary**, alongside the
existing node importance and stage progression.

## 10. Experiment tracking

`experiments.py` appends one immutable JSONL record per run: hyperparameters,
dataset, graph strategy, architecture, metrics, training time, checkpoint path,
mode, and (optionally) the short **git commit**.

## 11. Reports

`reports.py` renders an evaluation report as **JSON / CSV / HTML**. The HTML
report is print-ready — “Save as PDF” in the browser produces the PDF deliverable
without a heavyweight PDF dependency.

## 12. Research Dashboard

`/research` (sidebar → *Research Lab*) provides tabs for Dataset Versions,
Drift, Model Evolution (accuracy/F1 trend), Experiments, Retrain & Approve
(candidate compare + approval), Review Queue and Knowledge Base, plus report
download buttons.

---

## 13. API reference (Phase 12)

Express base `/api` proxies to AI `/api/v1`. All routes require auth; write
actions require the `train`/`predict` permission.

| Method & path (Express) | AI route | Purpose |
| --- | --- | --- |
| `GET /api/datasets/versions` | `GET /datasets` | list dataset versions |
| `GET /api/datasets/history` | `GET /datasets/history` | flat version history |
| `POST /api/datasets/register` | `POST /datasets` | collect + version + drift |
| `GET /api/drift` | `GET /drift` | recent drift reports |
| `POST /api/drift` | `POST /drift` | compute drift vs baseline |
| `GET /api/experiments` | `GET /experiments` | experiment log |
| `GET /api/training/history` | `GET /training/history` | log + accuracy trend |
| `POST /api/retrain` | `POST /retrain` | train candidate (not activated) |
| `POST /api/compare` | `POST /compare` | active vs candidate |
| `POST /api/approve-model` | `POST /approve-model` | activate candidate |
| `GET /api/review` | `GET /review` | review queue + stats |
| `POST /api/review/:id/relabel` | `POST /review/{id}/relabel` | relabel sample |
| `POST /api/review/:id/approve` | `POST /review/{id}/approve` | approve sample |
| `GET /api/knowledge-base` | `GET /knowledge-base` | KB summary |
| `GET /api/reports/evaluation?format=` | `GET /reports` | json/csv/html report |

---

## 14. Security properties

* **Dataset poisoning** — quality screening rejects invalid data before it is
  ever stored or trained on.
* **Duplicate training** — content-hash de-duplication of dataset versions.
* **Invalid labels** — unknown labels flagged (and heavily-unknown datasets
  rejected).
* **Corrupted CSV** — corrupted/all-NaN/non-finite rows detected in the report.
* **Unsafe model replacement** — candidates are never auto-activated; promotion
  requires explicit approval and only replaces the active model when the
  candidate is not worse.

---

## 15. Research justification & future scope

Continual learning with drift-gated, human-approved model promotion mirrors
production MLOps best practice (e.g. champion/challenger with shadow evaluation)
while remaining reproducible for a research setting (immutable dataset versions +
append-only experiment log + git commit provenance).

**Future scope:** streaming folder-watcher ingestion into `register_dataframe`,
learned drift thresholds, replay-based rehearsal to combat catastrophic
forgetting, uncertainty via MC-dropout/ensembles for active learning, and a
native PDF export backend.
