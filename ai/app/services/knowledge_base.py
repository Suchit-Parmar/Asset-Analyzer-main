"""AI knowledge base (Phase 12, step 10).

Maintains a living summary of what the platform knows about attacks:

  * Known attacks      – the supported taxonomy with MITRE tactic/technique and
    threat level.
  * Historical attacks – classes actually observed across registered dataset
    versions (with aggregate counts).
  * Unknown attacks    – labels flagged as out-of-taxonomy by data-quality /
    review queue, awaiting human triage.
  * Emerging patterns  – classes whose share is rising in the most recent
    dataset version compared to earlier ones.

Everything is derived on demand from existing artefacts (dataset versions,
review queue) so the knowledge base is always consistent with reality.
"""

from __future__ import annotations

from typing import Any

from app.models.tgnn import ATTACK_TYPES
from app.services.dataset_manager import dataset_manager
from app.services.review_queue import review_queue

# Compact MITRE + threat mapping (kept local to avoid importing the heavy
# inference service just for constants).
_MITRE = {
    "Normal": ("None", "None", "low"),
    "DDoS": ("Impact", "T1498", "critical"),
    "DoS": ("Impact", "T1499", "critical"),
    "Probe": ("Reconnaissance", "T1046", "medium"),
    "R2L": ("Initial Access", "T1078", "high"),
    "U2R": ("Privilege Escalation", "T1068", "critical"),
    "Botnet": ("Command and Control", "T1071", "high"),
    "Web Attack": ("Initial Access", "T1190", "high"),
    "Infiltration": ("Lateral Movement", "T1021", "critical"),
    "Brute Force": ("Credential Access", "T1110", "high"),
    "Heartbleed": ("Privilege Escalation", "T1068", "critical"),
}


def _known_attacks() -> list[dict[str, Any]]:
    out = []
    for name in ATTACK_TYPES:
        tactic, technique, threat = _MITRE.get(name, ("Unknown", "T0000", "medium"))
        out.append({
            "name": name,
            "mitre_tactic": tactic,
            "mitre_technique": technique,
            "threat_level": threat,
        })
    return out


def summary() -> dict[str, Any]:
    """Assemble the current knowledge-base summary."""
    history = dataset_manager.history()

    # Historical class counts aggregated across all dataset versions.
    historical: dict[str, int] = {}
    for version in history:
        for cls, cnt in (version.get("attack_distribution") or {}).items():
            historical[cls] = historical.get(cls, 0) + int(cnt)

    # Emerging patterns: compare newest version's class share vs the rest.
    emerging: list[dict[str, Any]] = []
    if len(history) >= 2:
        newest = history[0].get("attack_distribution") or {}
        newest_total = max(sum(newest.values()), 1)
        prior: dict[str, int] = {}
        for version in history[1:]:
            for cls, cnt in (version.get("attack_distribution") or {}).items():
                prior[cls] = prior.get(cls, 0) + int(cnt)
        prior_total = max(sum(prior.values()), 1)
        for cls, cnt in newest.items():
            new_share = cnt / newest_total
            old_share = prior.get(cls, 0) / prior_total
            if new_share - old_share > 0.05:
                emerging.append({
                    "name": cls,
                    "new_share": round(new_share, 4),
                    "previous_share": round(old_share, 4),
                    "delta": round(new_share - old_share, 4),
                })
        emerging.sort(key=lambda e: e["delta"], reverse=True)

    # Unknown attacks: labels flagged by the review queue / dataset quality.
    unknown: dict[str, int] = {}
    for version in history:
        for label, cnt in ((version.get("attack_distribution") or {}).items()):
            known = any(label.lower() == a.lower() for a in ATTACK_TYPES) or label.lower() in (
                "benign", "normal", "0"
            )
            if not known:
                unknown[label] = unknown.get(label, 0) + int(cnt)
    review_stats = review_queue.stats()

    return {
        "known_attacks": _known_attacks(),
        "historical_attacks": [
            {"name": k, "count": v}
            for k, v in sorted(historical.items(), key=lambda kv: kv[1], reverse=True)
        ],
        "unknown_attacks": [
            {"name": k, "count": v}
            for k, v in sorted(unknown.items(), key=lambda kv: kv[1], reverse=True)
        ],
        "emerging_patterns": emerging,
        "review_queue": review_stats,
        "summary": (
            f"{len(ATTACK_TYPES)} known attack classes; "
            f"{len(historical)} observed across {len(history)} dataset version(s); "
            f"{len(unknown)} unknown label(s); "
            f"{len(emerging)} emerging pattern(s); "
            f"{review_stats.get('pending', 0)} sample(s) awaiting review."
        ),
    }


knowledge_base = summary  # callable alias
