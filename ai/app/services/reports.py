"""Automatic evaluation reports (Phase 12, step 13).

Builds a single, self-contained report from the artefacts the platform already
produces (active model metrics, experiment history, latest drift analysis and
dataset statistics) and renders it as JSON, CSV or HTML.

The HTML report is print-ready — opening it in a browser and choosing "Save as
PDF" yields the PDF deliverable without pulling in a heavyweight PDF dependency,
which keeps the research prototype easy to install.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from typing import Any


def build_report(model_id: str | None = None) -> dict[str, Any]:
    """Gather everything needed for an evaluation report into one dict."""
    from app.services.dataset_manager import dataset_manager
    from app.services.experiments import experiment_store
    from app.services.training import training_service

    model = training_service.get_metrics(model_id)
    metrics = model.get("metrics", {}) if isinstance(model, dict) else {}

    experiments = experiment_store.list(limit=50)
    datasets = dataset_manager.history()

    return {
        "generated_at": datetime.utcnow().isoformat(),
        "model": {
            "architecture": model.get("architecture"),
            "dataset_id": model.get("dataset_id"),
            "trained_at": model.get("trained_at"),
            "graph_strategy": model.get("graph_strategy"),
        },
        "metrics": {
            "accuracy": metrics.get("accuracy"),
            "precision": metrics.get("precision"),
            "recall": metrics.get("recall"),
            "f1": metrics.get("f1"),
            "macro_f1": metrics.get("macro_f1"),
            "weighted_f1": metrics.get("weighted_f1"),
            "roc_auc": metrics.get("roc_auc"),
            "best_epoch": metrics.get("best_epoch"),
            "test": metrics.get("test"),
            "validation": metrics.get("validation"),
            "confusion_matrix": metrics.get("confusion_matrix"),
            "class_labels": metrics.get("class_labels"),
            "per_class": metrics.get("per_class"),
            "training_curve": metrics.get("history"),
            "training_time_sec": metrics.get("training_time_sec"),
            "inference_time_ms": metrics.get("inference_time_ms"),
            "graph_stats": metrics.get("graph_stats"),
        },
        "experiments": experiments,
        "datasets": datasets,
    }


def to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, default=str)


def to_csv(report: dict[str, Any]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    m = report.get("metrics", {})
    writer.writerow(["section", "metric", "value"])
    for key in ("accuracy", "precision", "recall", "f1", "macro_f1",
                "weighted_f1", "roc_auc", "best_epoch",
                "training_time_sec", "inference_time_ms"):
        writer.writerow(["overall", key, m.get(key)])

    writer.writerow([])
    writer.writerow(["class", "precision", "recall", "f1", "support"])
    for cls, vals in (m.get("per_class") or {}).items():
        writer.writerow([cls, vals.get("precision"), vals.get("recall"),
                         vals.get("f1"), vals.get("support")])
    return buf.getvalue()


def _fmt(v: Any) -> str:
    if v is None:
        return "—"
    if isinstance(v, float):
        return f"{v:.4f}"
    return str(v)


def to_html(report: dict[str, Any]) -> str:
    m = report.get("metrics", {})
    model = report.get("model", {})

    def metric_cards() -> str:
        cards = []
        for label, key in [
            ("Accuracy", "accuracy"), ("Precision", "precision"),
            ("Recall", "recall"), ("F1", "f1"), ("Macro F1", "macro_f1"),
            ("ROC-AUC", "roc_auc"),
        ]:
            cards.append(
                f'<div class="card"><div class="k">{label}</div>'
                f'<div class="v">{_fmt(m.get(key))}</div></div>'
            )
        return "".join(cards)

    def per_class_rows() -> str:
        rows = []
        for cls, vals in (m.get("per_class") or {}).items():
            rows.append(
                f"<tr><td>{cls}</td><td>{_fmt(vals.get('precision'))}</td>"
                f"<td>{_fmt(vals.get('recall'))}</td><td>{_fmt(vals.get('f1'))}</td>"
                f"<td>{_fmt(vals.get('support'))}</td></tr>"
            )
        return "".join(rows) or '<tr><td colspan="5">No per-class data.</td></tr>'

    def confusion_html() -> str:
        cm = m.get("confusion_matrix")
        labels = m.get("class_labels") or []
        if not cm:
            return "<p>No confusion matrix available.</p>"
        head = "".join(f"<th>{l}</th>" for l in labels)
        body = ""
        for i, row in enumerate(cm):
            label = labels[i] if i < len(labels) else str(i)
            cells = "".join(f"<td>{c}</td>" for c in row)
            body += f"<tr><th>{label}</th>{cells}</tr>"
        return f'<table class="cm"><tr><th></th>{head}</tr>{body}</table>'

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>GNN-IDS Evaluation Report</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 40px; color: #0f172a; }}
  h1 {{ margin-bottom: 4px; }}
  .muted {{ color: #64748b; font-size: 13px; }}
  .cards {{ display: flex; flex-wrap: wrap; gap: 12px; margin: 20px 0; }}
  .card {{ border: 1px solid #e2e8f0; border-radius: 12px; padding: 14px 18px; min-width: 120px; }}
  .card .k {{ font-size: 12px; color: #64748b; }}
  .card .v {{ font-size: 22px; font-weight: 600; }}
  table {{ border-collapse: collapse; width: 100%; margin: 12px 0; font-size: 13px; }}
  th, td {{ border: 1px solid #e2e8f0; padding: 6px 10px; text-align: center; }}
  th {{ background: #f8fafc; }}
  table.cm td {{ font-variant-numeric: tabular-nums; }}
  @media print {{ .noprint {{ display:none; }} }}
</style></head>
<body>
  <h1>GNN-IDS Evaluation Report</h1>
  <div class="muted">Generated {report.get('generated_at')} ·
    Model: {model.get('architecture') or '—'} ·
    Dataset: {model.get('dataset_id') or '—'} ·
    Graph: {model.get('graph_strategy') or '—'}</div>
  <p class="noprint muted">Tip: use your browser's “Save as PDF” to export this report.</p>

  <h2>Headline metrics</h2>
  <div class="cards">{metric_cards()}</div>
  <div class="muted">Training time: {_fmt(m.get('training_time_sec'))}s ·
    Inference: {_fmt(m.get('inference_time_ms'))} ms/snapshot ·
    Best epoch: {_fmt(m.get('best_epoch'))}</div>

  <h2>Per-class metrics</h2>
  <table><tr><th>Class</th><th>Precision</th><th>Recall</th><th>F1</th><th>Support</th></tr>
    {per_class_rows()}</table>

  <h2>Confusion matrix</h2>
  {confusion_html()}

  <h2>Recent experiments</h2>
  <div class="muted">{len(report.get('experiments', []))} run(s) ·
    {len(report.get('datasets', []))} dataset version(s) tracked.</div>
</body></html>"""


def render(report: dict[str, Any], fmt: str = "json") -> tuple[str, str]:
    """Return ``(content, media_type)`` for the requested format."""
    fmt = (fmt or "json").lower()
    if fmt == "csv":
        return to_csv(report), "text/csv"
    if fmt in ("html", "pdf"):
        # PDF is delivered as print-ready HTML (browser → Save as PDF).
        return to_html(report), "text/html"
    return to_json(report), "application/json"
