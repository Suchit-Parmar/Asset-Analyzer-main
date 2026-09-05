"""SOC Response Engine (Phase 8).

For every prediction the platform can generate an actionable Security
Operations Center (SOC) response bundle:

* MITRE ATT&CK tactic / technique (with reference URL)
* Lockheed-Martin Cyber Kill Chain stage
* Severity + confidence
* Recommended analyst action + ordered response playbook
* Containment artefacts: firewall rule (iptables + Windows netsh) and a
  host-isolation command
* Detection rules: Sigma (YAML), YARA, Suricata and Snort
* Analyst notes and a plain-language risk summary

Everything is generated deterministically from the prediction so the same
attack always yields the same, reproducible rules (stable Suricata/Snort SIDs,
etc.). This module has no side effects and no external dependencies, so it can
be called safely from the inference hot-path.
"""

from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

# Lockheed-Martin Cyber Kill Chain phase per MITRE tactic. Falls back to a
# per-attack-type mapping when the tactic is unknown.
_TACTIC_TO_KILL_CHAIN = {
    "Reconnaissance": "Reconnaissance",
    "Resource Development": "Weaponization",
    "Initial Access": "Delivery",
    "Execution": "Exploitation",
    "Persistence": "Installation",
    "Privilege Escalation": "Exploitation",
    "Defense Evasion": "Exploitation",
    "Credential Access": "Exploitation",
    "Discovery": "Reconnaissance",
    "Lateral Movement": "Command & Control",
    "Collection": "Actions on Objectives",
    "Command and Control": "Command & Control",
    "Exfiltration": "Actions on Objectives",
    "Impact": "Actions on Objectives",
    "None": "None",
}

# Attack-type specific SOC playbooks. Each entry drives the recommended action,
# the ordered response steps and the free-text detection focus embedded in the
# generated rules.
_PLAYBOOKS: dict[str, dict[str, Any]] = {
    "DDoS": {
        "action": "Engage DDoS mitigation / rate-limiting and enable upstream scrubbing.",
        "steps": [
            "Enable rate-limiting and SYN-cookie protection on edge devices.",
            "Divert traffic to an upstream scrubbing / CDN provider.",
            "Block the top offending source ranges at the perimeter firewall.",
            "Notify the on-call network team and open a SEV incident.",
        ],
        "sigma_level": "high",
        "detection": "high-volume traffic from a single or distributed set of sources",
    },
    "DoS": {
        "action": "Apply connection rate-limiting and block the offending source.",
        "steps": [
            "Rate-limit connections from the source at the firewall.",
            "Verify service health and fail over if resources are exhausted.",
            "Capture a packet sample for post-incident analysis.",
        ],
        "sigma_level": "high",
        "detection": "abnormal connection/packet rate towards a single service",
    },
    "Probe": {
        "action": "Monitor the source and tighten exposed service exposure.",
        "steps": [
            "Add the scanning source to a watch-list.",
            "Confirm exposed ports are intended and firewalled where possible.",
            "Enable port-scan detection alerting.",
        ],
        "sigma_level": "medium",
        "detection": "sequential connection attempts across many ports/hosts",
    },
    "Reconnaissance": {
        "action": "Track the reconnaissance source and reduce information exposure.",
        "steps": [
            "Log and watch-list the reconnaissance source.",
            "Review banner/version disclosure on exposed services.",
            "Correlate with prior activity from the same subnet.",
        ],
        "sigma_level": "medium",
        "detection": "scanning / enumeration activity across multiple ports",
    },
    "Brute Force": {
        "action": "Lock affected accounts, enforce MFA and block the source.",
        "steps": [
            "Temporarily lock the targeted account(s).",
            "Block the source IP at the firewall.",
            "Enforce MFA and rotate exposed credentials.",
            "Review authentication logs for a successful login.",
        ],
        "sigma_level": "high",
        "detection": "repeated failed authentication attempts from one source",
    },
    "R2L": {
        "action": "Isolate the target host and rotate credentials.",
        "steps": [
            "Isolate the affected host from the network.",
            "Rotate credentials that may have been exposed.",
            "Hunt for unauthorized remote-access sessions.",
        ],
        "sigma_level": "high",
        "detection": "unauthorized remote-to-local access attempts",
    },
    "U2R": {
        "action": "Isolate host immediately; suspected privilege escalation.",
        "steps": [
            "Isolate the host and preserve volatile memory for forensics.",
            "Disable the compromised local account.",
            "Audit for persistence mechanisms and suid/root shells.",
        ],
        "sigma_level": "critical",
        "detection": "local privilege-escalation / root-shell activity",
    },
    "Botnet": {
        "action": "Block C2 destinations and isolate infected hosts.",
        "steps": [
            "Block known C2 domains/IPs at DNS and firewall.",
            "Isolate infected hosts and image them for analysis.",
            "Hunt for beaconing behaviour across the fleet.",
        ],
        "sigma_level": "high",
        "detection": "periodic beaconing to command-and-control infrastructure",
    },
    "Exploits": {
        "action": "Patch the targeted service and isolate the host.",
        "steps": [
            "Isolate the targeted host.",
            "Apply vendor patches for the exploited service.",
            "Scan for indicators of successful exploitation.",
        ],
        "sigma_level": "high",
        "detection": "exploitation attempt against a vulnerable service",
    },
    "Web Attack": {
        "action": "Enable WAF blocking and review the targeted endpoint.",
        "steps": [
            "Enable / tune WAF rules for the targeted endpoint.",
            "Review web-server and application logs for the payload.",
            "Patch the affected application if a vulnerability is confirmed.",
        ],
        "sigma_level": "high",
        "detection": "malicious HTTP payloads (SQLi / XSS / traversal)",
    },
    "Infiltration": {
        "action": "Isolate host, hunt for lateral movement and persistence.",
        "steps": [
            "Isolate the affected host from the network.",
            "Hunt for lateral movement to adjacent hosts.",
            "Rotate credentials and review privileged account usage.",
        ],
        "sigma_level": "critical",
        "detection": "internal lateral movement / unauthorized internal access",
    },
    "Heartbleed": {
        "action": "Patch OpenSSL immediately and rotate all secrets.",
        "steps": [
            "Patch OpenSSL to a non-vulnerable version.",
            "Revoke and re-issue TLS certificates.",
            "Rotate all potentially exposed secrets and session tokens.",
        ],
        "sigma_level": "critical",
        "detection": "malformed TLS heartbeat requests (CVE-2014-0160)",
    },
    "Fuzzers": {
        "action": "Monitor the source and harden input validation.",
        "steps": [
            "Watch-list the source generating malformed input.",
            "Review service crash / error logs.",
            "Harden input validation on the targeted service.",
        ],
        "sigma_level": "medium",
        "detection": "malformed / anomalous protocol input (fuzzing)",
    },
    "Generic": {
        "action": "Investigate anomalous execution and contain if confirmed.",
        "steps": [
            "Triage the alert and validate against baseline behaviour.",
            "Contain the source if malicious activity is confirmed.",
        ],
        "sigma_level": "medium",
        "detection": "generic anomalous execution behaviour",
    },
    "Normal": {
        "action": "No action required — traffic classified as benign.",
        "steps": ["No response required. Continue routine monitoring."],
        "sigma_level": "informational",
        "detection": "benign baseline traffic",
    },
}

_DEFAULT_PLAYBOOK = {
    "action": "Investigate the anomaly and escalate to a SOC analyst.",
    "steps": [
        "Triage the alert and gather surrounding context.",
        "Escalate to a Tier-2 analyst if malicious activity is suspected.",
    ],
    "sigma_level": "medium",
    "detection": "anomalous network behaviour",
}

_SEVERITY_ORDER = {"low": 1, "informational": 1, "medium": 2, "high": 3, "critical": 4}


def _stable_sid(attack_type: str) -> int:
    """Deterministic Suricata/Snort SID in the local rule range (1,000,000+)."""
    h = 0
    for ch in attack_type:
        h = (h * 31 + ord(ch)) & 0xFFFFFF
    return 1_000_000 + (h % 900_000)


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_") or "attack"


def _severity(threat_level: str, confidence: float) -> str:
    base = (threat_level or "medium").lower()
    if base not in _SEVERITY_ORDER:
        base = "medium"
    # Low-confidence predictions are de-escalated one level (never below low).
    if confidence < 0.5 and base != "low":
        downgraded = {"critical": "high", "high": "medium", "medium": "low"}
        return downgraded.get(base, base)
    return base


def _sigma_rule(attack_type: str, technique: str, tactic: str, detection: str,
                level: str, source_ip: str | None) -> str:
    condition = "selection"
    src_line = f"    src_ip: '{source_ip}'\n" if source_ip else ""
    return (
        f"title: {attack_type} Activity Detected (TGNN)\n"
        f"id: tgnn-{_slug(attack_type)}\n"
        "status: experimental\n"
        f"description: Detects {detection}. Auto-generated by the TGNN SOC engine.\n"
        "author: TGNN SOC Response Engine\n"
        "tags:\n"
        f"  - attack.{_slug(tactic)}\n"
        f"  - attack.{technique.lower()}\n"
        "logsource:\n"
        "  category: network_connection\n"
        "detection:\n"
        "  selection:\n"
        f"    classification: '{attack_type}'\n"
        f"{src_line}"
        f"  condition: {condition}\n"
        f"level: {level}\n"
    )


def _yara_rule(attack_type: str, technique: str, detection: str) -> str:
    rule_name = f"TGNN_{_slug(attack_type).title().replace('_', '')}"
    return (
        f"rule {rule_name}\n"
        "{\n"
        "    meta:\n"
        f"        description = \"Behavioural indicators for {attack_type} ({detection})\"\n"
        f"        mitre_technique = \"{technique}\"\n"
        "        author = \"TGNN SOC Response Engine\"\n"
        "    strings:\n"
        f"        $a = \"{attack_type}\" nocase\n"
        f"        $b = \"{_slug(attack_type)}\" nocase\n"
        "    condition:\n"
        "        any of them\n"
        "}\n"
    )


def _suricata_rule(attack_type: str, detection: str, sid: int,
                   source_ip: str | None, target_ip: str | None,
                   protocol: str | None) -> str:
    proto = (protocol or "ip").lower()
    if proto not in ("ip", "tcp", "udp", "icmp", "http", "dns", "tls"):
        proto = "ip"
    src = source_ip or "$EXTERNAL_NET"
    dst = target_ip or "$HOME_NET"
    return (
        f'alert {proto} {src} any -> {dst} any '
        f'(msg:"TGNN {attack_type} - {detection}"; '
        f'flow:to_server; classtype:trojan-activity; '
        f'sid:{sid}; rev:1;)'
    )


def _snort_rule(attack_type: str, detection: str, sid: int,
                source_ip: str | None, target_ip: str | None,
                protocol: str | None) -> str:
    proto = (protocol or "ip").lower()
    if proto not in ("ip", "tcp", "udp", "icmp"):
        proto = "ip"
    src = source_ip or "any"
    dst = target_ip or "$HOME_NET"
    return (
        f'alert {proto} {src} any -> {dst} any '
        f'(msg:"TGNN {attack_type} - {detection}"; '
        f'classtype:attempted-recon; sid:{sid + 1}; rev:1;)'
    )


def _firewall_rule(source_ip: str | None, port: int | str | None) -> dict[str, str]:
    if not source_ip:
        return {
            "linux": "# No source IP available — apply rate-limiting at the perimeter.",
            "windows": "# No source IP available — apply rate-limiting at the perimeter.",
        }
    port_clause = f" --dport {port}" if port else ""
    return {
        "linux": f"iptables -A INPUT -s {source_ip}{port_clause} -j DROP",
        "windows": (
            f'netsh advfirewall firewall add rule name="Block_{source_ip}" '
            f'dir=in action=block remoteip={source_ip}'
        ),
    }


def _isolation_command(target_ip: str | None) -> str:
    if not target_ip:
        return "# Identify the affected host, then quarantine via EDR/NAC."
    return (
        f"# Quarantine host {target_ip} (EDR example):\n"
        f"edr-cli host isolate --ip {target_ip} --reason \"TGNN detection\""
    )


def build_soc_response(
    *,
    attack_type: str,
    attack_stage: str | None = None,
    confidence: float = 0.0,
    threat_level: str = "medium",
    risk_score: float = 0.0,
    mitre_tactic: str = "Unknown",
    mitre_technique: str = "T0000",
    source_ip: str | None = None,
    target_ip: str | None = None,
    protocol: str | None = None,
    port: int | str | None = None,
) -> dict[str, Any]:
    """Generate a complete, reproducible SOC response bundle for a prediction."""
    playbook = _PLAYBOOKS.get(attack_type, _DEFAULT_PLAYBOOK)
    kill_chain = _TACTIC_TO_KILL_CHAIN.get(mitre_tactic, "Exploitation")
    if attack_type == "Normal":
        kill_chain = "None"
    severity = _severity(threat_level, confidence)
    detection = playbook["detection"]
    level = playbook["sigma_level"]
    sid = _stable_sid(attack_type)

    technique_url = (
        f"https://attack.mitre.org/techniques/{mitre_technique.replace('.', '/')}/"
        if mitre_technique and mitre_technique not in ("None", "T0000")
        else None
    )

    benign = attack_type == "Normal"

    detection_rules = {
        "sigma": _sigma_rule(attack_type, mitre_technique, mitre_tactic, detection, level, source_ip),
        "yara": _yara_rule(attack_type, mitre_technique, detection),
        "suricata": _suricata_rule(attack_type, detection, sid, source_ip, target_ip, protocol),
        "snort": _snort_rule(attack_type, detection, sid, source_ip, target_ip, protocol),
    }

    risk_summary = (
        f"Traffic classified as benign ({round(confidence * 100)}% confidence). "
        "No containment required."
        if benign
        else (
            f"{attack_type} ({severity.upper()} severity) detected with "
            f"{round(confidence * 100)}% confidence and risk score "
            f"{round(risk_score * 100)}%. MITRE tactic: {mitre_tactic} "
            f"({mitre_technique}). Kill-chain stage: {kill_chain}. "
            f"Recommended: {playbook['action']}"
        )
    )

    analyst_notes = (
        "Prediction confidence is low — treat as a lead and corroborate with "
        "additional telemetry before acting."
        if confidence < 0.5 and not benign
        else (
            "High-confidence detection — proceed with the recommended containment "
            "playbook and document actions in the incident ticket."
            if not benign
            else "Benign classification — logged for baseline; no ticket required."
        )
    )

    return {
        "attack_type": attack_type,
        "attack_stage": attack_stage,
        "mitre": {
            "tactic": mitre_tactic,
            "technique": mitre_technique,
            "technique_url": technique_url,
        },
        "kill_chain_stage": kill_chain,
        "severity": severity,
        "confidence": round(float(confidence), 4),
        "risk_score": round(float(risk_score), 4),
        "recommended_action": playbook["action"],
        "recommended_response": list(playbook["steps"]),
        "firewall_rule": _firewall_rule(source_ip, port),
        "isolation_command": _isolation_command(target_ip),
        "detection_rules": detection_rules,
        "analyst_notes": analyst_notes,
        "risk_summary": risk_summary,
    }


class SOCResponseEngine:
    """Thin OO wrapper so callers can `from ... import soc_engine`."""

    def build(self, **kwargs: Any) -> dict[str, Any]:
        return build_soc_response(**kwargs)

    def from_prediction(self, prediction: dict[str, Any],
                        *, source_ip: str | None = None,
                        target_ip: str | None = None,
                        protocol: str | None = None,
                        port: int | str | None = None) -> dict[str, Any]:
        """Build a SOC response from an inference `predict()` result dict."""
        return build_soc_response(
            attack_type=prediction.get("attack_type", "Generic"),
            attack_stage=prediction.get("attack_stage"),
            confidence=float(prediction.get("confidence", 0.0)),
            threat_level=prediction.get("threat_level", "medium"),
            risk_score=float(prediction.get("risk_score", 0.0)),
            mitre_tactic=prediction.get("mitre_tactic", "Unknown"),
            mitre_technique=prediction.get("mitre_technique", "T0000"),
            source_ip=source_ip,
            target_ip=target_ip,
            protocol=protocol,
            port=port,
        )


soc_engine = SOCResponseEngine()
