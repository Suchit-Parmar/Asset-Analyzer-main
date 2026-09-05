# Graph Construction Strategies (Module C)

The platform builds graphs from network-flow datasets before training/inference.
As of Module C the construction method is **selectable and fully wired end-to-end**:

```
Model Studio (frontend)
    → Express  /api/training/start | /api/graph/build | /api/config
        → AI service  /api/v1/train | /api/v1/graph/build | /api/v1/config
            → app/graph/strategies.build_snapshots(df, GraphConfig)
                → training  (app/services/training.py)
                → inference (app/services/inference.py, via /predict/from-dataset)
```

All strategies emit the **same snapshot schema** (16-dim node features + edge
index + graph-level label), so the TGNN model, checkpoints and dashboards are
unchanged. The model classifies at the graph level (global mean pooling), which
is why any node definition (endpoint or flow) is compatible.

Source of truth: [`ai/app/graph/strategies.py`](../ai/app/graph/strategies.py).

---

## 1. Endpoint Graph (`endpoint`)

- **Nodes**: network endpoints — real `Src/Dst IP` when the dataset provides them,
  otherwise deterministic endpoint IDs derived from flow characteristics (Module B).
- **Edges**: observed communications between endpoints, per fixed-size row chunk.
- **Parameters**: `directed` (directed vs undirected), `rows_per_graph`.
- **Advantages**: intuitive host-level topology; good for lateral-movement and
  scanning patterns; small node counts.
- **Limitations**: aggregates many flows per node, so fine-grained per-flow
  signals are blurred; not time-aware.
- **Recommended for**: host-centric intrusion patterns, network topology analysis.

## 2. Flow Graph (`flow`)

- **Nodes**: individual network flows (one node per flow record).
- **Edges**: sequential/related flows — flow *i* connects to the next
  `flow_sequential_distance` flows.
- **Parameters**: `flow_sequential_distance`, `directed`, `rows_per_graph`.
- **Advantages**: preserves per-flow features; captures short-range temporal
  ordering of flows.
- **Limitations**: no host topology; edge structure is a simple chain unless the
  distance is increased.
- **Recommended for**: sequence-sensitive attacks (e.g. multi-stage bursts).

## 3. Feature Similarity Graph (`similarity`)

- **Nodes**: flows.
- **Edges**: connect flows whose feature vectors are similar.
  - `cosine`: connect pairs with cosine similarity ≥ `similarity_threshold`.
  - `knn`: connect each flow to its `similarity_neighbors` nearest neighbours.
- **Parameters**: `similarity_metric` (`cosine`|`knn`), `similarity_threshold`,
  `similarity_neighbors`, `rows_per_graph` (capped by `max_flow_nodes`).
- **Advantages**: groups behaviourally similar flows regardless of order; dense,
  informative neighbourhoods for message passing.
- **Limitations**: O(n²) similarity per chunk (bounded by `max_flow_nodes`);
  threshold/k must be tuned; edges are inherently undirected.
- **Recommended for**: clustering-style detection, campaigns of similar flows.

## 4. Temporal Sliding Window Graph (`temporal`, default)

- **Nodes**: endpoints within a time window.
- **Edges**: communications inside the window; multiple overlapping windows
  produce a sequence of snapshots.
- **Parameters**: `window_size` (seconds), `window_overlap` (0–0.95), or an
  explicit `window_stride` (seconds).
- **Advantages**: time-aware; produces many snapshots (good for temporal models
  and for a robust train/val/test split); reflects evolving attack stages.
- **Limitations**: window size/overlap strongly affect snapshot count and
  density; very large spans with tiny strides are capped for safety.
- **Recommended for**: temporal attack-stage prediction (the project default).

---

## Configuration & persistence

Model Studio settings (strategy, parameters, feature set, hyperparameters) are
saved via `POST /api/config` and auto-loaded via `GET /api/config` on page load.
They are persisted as JSON at `ai/config/studio_config.json`
(see [`ai/app/services/config_store.py`](../ai/app/services/config_store.py)).

## Metadata & evaluation

Every trained checkpoint records, under `metrics`:

- `graph_strategy`, `graph_params`, `feature_set`, `dataset_id`, `trained_at`
- `graph_stats`: `num_snapshots`, `avg_nodes`, `avg_edges`, `avg_density`,
  `avg_degree`
- `training_time_sec`, `inference_time_ms`
- full evaluation: accuracy, macro/weighted precision/recall/F1, ROC-AUC,
  confusion matrix, per-class metrics (held-out test split — Module A)

These are surfaced by `GET /api/model/info` and `GET /api/metrics`, so Model
Studio can display and compare strategies. To compare strategies, train one model
per strategy (the dropdown makes each selectable) and read back the recorded
`graph_stats` + metrics for a side-by-side table.

## Research justification

Comparing graph construction strategies on identical flow data isolates the
effect of relational structure on GNN detection performance — a standard ablation
in graph-based IDS research. Endpoint/temporal graphs test host- and time-centric
inductive biases; flow and similarity graphs test flow-centric and behavioural
biases. Reporting held-out test metrics plus graph-structure statistics
(nodes/edges/density/degree) and timing makes the comparison reproducible and
publishable.

## Scalability & memory efficiency (Module D)

Large datasets (250K–1M+ rows) are handled without exhausting memory:

- **Streaming loaders** — CICIDS2017, UNSW-NB15 and CSE-CIC-IDS2018 read CSVs in
  50K-row chunks with per-file attack/benign budgets derived from `max_rows`, so
  whole files are never materialized (`ai/app/data/loaders.py`).
- **Bounded snapshot count** — `GraphConfig.max_snapshots` (default 5000) caps how
  many graphs are built. For row-chunked strategies the chunk size auto-grows
  (`_effective_chunk_size`) so every row is still covered with fewer, larger
  graphs; temporal/oversized results are evenly subsampled (`_cap_snapshots`).
- **Lazy chunk iteration** — chunks are streamed via a generator, not a
  materialized list.
- **Training memory hygiene** — the raw dataframe is released (`del df` + GC) once
  snapshots are built, before the training loop.

Verified: 300K synthetic rows → 600 snapshots (endpoint) built in ~7s; the
snapshot count stays under `max_snapshots` while small datasets keep their base
chunking unchanged. To train on more rows, raise `max_rows` in the Model Studio
hyperparameters (or the `/train` request).

## Backward compatibility

- Legacy strategy names are aliased (`static → endpoint`, `tgn`/`continuous →
  temporal`, `feature_similarity → similarity`, `sliding_window → temporal`).
- The strategy may be passed as top-level `graph_strategy`/`graph_params` **or**
  nested inside `hyperparameters` — old callers keep working.
- Older checkpoints without strategy metadata still load (fields report `null`).
- `assign_synthetic_ips` remains as an alias of `assign_endpoints`.
