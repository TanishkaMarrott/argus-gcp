"""
Hooks — deterministic post-processing. No LLM. Pure functions.
Applied after remediator runs. Enrich every finding with:
  - SOC 2 control mapping
  - Evidence ID
  - SLA due date
  - Zero-tolerance flag
  - Status (always OPEN — humans close, not the panel)
"""

import datetime
import hashlib
import uuid

from .skills import auditor_evidence, is_zero_tolerance, skill_for_finding, sla_days

CONTROL_MAP = {
    "primitive_role":          "CC6.3",
    "public_binding":          "CC6.1",
    "stale_key":               "CC6.3",
    "ssl_not_required":        "CC6.7",
    "public_ip":               "CC6.6",
    "open_authorized_network": "CC6.6",
    "backups_disabled":        "A1.2",
}

CONTROL_NAMES = {
    "CC6.1": "Logical and Physical Access Controls",
    "CC6.3": "Role-Based Access and Least Privilege",
    "CC6.6": "Logical Access Restrictions (Network)",
    "CC6.7": "Encryption in Transit",
    "A1.2":  "Availability — Backup and Recovery",
}


def apply(finding: dict, skills: list[dict]) -> dict:
    finding_type = finding.get("type", "")
    risk_level = finding.get("risk_level", "MEDIUM")
    found_at = finding.get("saved_at", datetime.datetime.now(datetime.timezone.utc).isoformat())

    control = CONTROL_MAP.get(finding_type, "CC9.2")
    skill = skill_for_finding(finding_type, skills)
    sla = sla_days(finding_type, risk_level, skills)
    due = _due_date(found_at, sla)

    return {
        **finding,
        "evidence_id":             _evidence_id(finding),
        "soc2_control":            control,
        "soc2_control_name":       CONTROL_NAMES.get(control, "General Security"),
        "soc2_skill":              skill.get("skill") if skill else None,
        "remediation_owner":       skill.get("remediation_owner", "platform-team") if skill else "platform-team",
        "zero_tolerance":          is_zero_tolerance(finding_type, skills),
        "sla_days":                sla,
        "due_date":                due,
        "auditor_evidence_needed": auditor_evidence(finding_type, skills),
        "status":                  "OPEN",   # humans close this, never the panel
    }


def _evidence_id(finding: dict) -> str:
    key = f"{finding.get('type')}|{finding.get('resource')}|{finding.get('member', '')}|{finding.get('key_id', '')}"
    short = hashlib.sha256(key.encode()).hexdigest()[:6].upper()
    return f"EVD-{short}"


def _due_date(found_at: str, sla: int) -> str:
    try:
        dt = datetime.datetime.fromisoformat(found_at.replace("Z", "+00:00"))
    except Exception:
        dt = datetime.datetime.now(datetime.timezone.utc)
    return (dt + datetime.timedelta(days=sla)).isoformat()
