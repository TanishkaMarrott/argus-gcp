"""
Skills loader — reads YAML skill files at runtime.
Each skill defines: SOC 2 control, finding types covered, SLAs, evidence needed.
Progressive disclosure: only load skills relevant to the current audit scope.
"""

import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

SKILLS_DIR = Path(__file__).parent.parent / "skills"


def load_skills(scope: list[str] | None = None) -> list[dict]:
    skills = []
    for path in sorted(SKILLS_DIR.glob("*.yaml")):
        try:
            skill = yaml.safe_load(path.read_text())
            if scope is None or skill.get("skill") in scope:
                skills.append(skill)
                logger.info(f"[skills] loaded {skill['skill']} → {skill['control']}")
        except Exception as e:
            logger.warning(f"[skills] failed to load {path.name}: {e}")
    return skills


def skill_for_finding(finding_type: str, skills: list[dict]) -> dict | None:
    for skill in skills:
        if finding_type in skill.get("finding_types", []):
            return skill
    return None


def sla_days(finding_type: str, risk_level: str, skills: list[dict]) -> int:
    skill = skill_for_finding(finding_type, skills)
    if skill:
        return skill.get("sla_days", {}).get(risk_level, 30)
    defaults = {"HIGH": 7, "MEDIUM": 30, "LOW": 90}
    return defaults.get(risk_level, 30)


def is_zero_tolerance(finding_type: str, skills: list[dict]) -> bool:
    skill = skill_for_finding(finding_type, skills)
    if skill:
        return finding_type in skill.get("zero_tolerance", [])
    return False


def auditor_evidence(finding_type: str, skills: list[dict]) -> list[str]:
    skill = skill_for_finding(finding_type, skills)
    if skill:
        return skill.get("auditor_evidence_needed", [])
    return ["Manual review of GCP Console"]


def skills_summary(skills: list[dict]) -> dict:
    return {s["skill"]: {"control": s["control"], "control_name": s["control_name"]} for s in skills}
