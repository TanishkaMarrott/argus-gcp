"""
Argus — GCP IAM & Database Security Auditor
SOC 2 Type II evidence collection pipeline.

Pipeline per run:
  load_skills
  → collect (rule-based, all findings)
  → panel + remediator IN PARALLEL on ALL findings (panel is a label, not a gate)
  → hooks (deterministic: control map, SLA, evidence ID, zero-tolerance flag)
  → store EVERYTHING append-only
  → report
"""

import asyncio
import datetime
import logging
import os
import uuid

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from pydantic import BaseModel

from argus.collector import collect
from argus.hooks import apply as apply_hooks
from argus.panel import run_panel
from argus.remediator import remediate
from argus.skills import load_skills, skills_summary
from argus.store import (get_latest_findings, get_open_findings, save_exception,
                         save_finding, save_report)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="Argus", description="GCP IAM & Database Security Auditor — SOC 2 evidence pipeline")

ARGUS_SECRET = os.environ.get("ARGUS_SECRET", "")


def _verify(secret: str | None) -> None:
    if ARGUS_SECRET and secret != ARGUS_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/health")
async def health():
    return {"status": "ok", "service": "argus"}


@app.post("/audit")
async def trigger_audit(request: Request, x_argus_secret: str | None = Header(default=None)):
    """Full audit run — called by Cloud Scheduler (daily)."""
    _verify(x_argus_secret)

    run_id = (
        f"run_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        f"_{uuid.uuid4().hex[:6]}"
    )
    logger.info(f"[argus] run={run_id} starting")

    # 1. Load skills — defines controls, SLAs, evidence requirements
    skills = load_skills()
    logger.info(f"[argus] skills loaded: {list(skills_summary(skills).keys())}")

    # 2. Collect — rule-based, no LLM
    raw_findings = await collect()
    logger.info(f"[argus] collected {len(raw_findings)} findings")

    if not raw_findings:
        summary = {
            "run_id": run_id, "total": 0,
            "skills": skills_summary(skills),
        }
        await save_report(run_id, summary)
        return summary

    # 3. Panel + remediator IN PARALLEL on ALL findings
    #    Panel = label only. Remediator always runs.
    panel_results, remediated_results = await asyncio.gather(
        asyncio.gather(*[run_panel(f) for f in raw_findings]),
        asyncio.gather(*[remediate(f) for f in raw_findings]),
    )

    # 4. Merge + apply deterministic hooks
    final_findings = []
    for panel, rem in zip(panel_results, remediated_results):
        merged = {
            **rem,
            "panel_verdict":        "CONFIRMED" if panel["panel_confirmed"] else "DISMISSED",
            "panel_confirmed_count": panel["panel_confirmed_count"],
            "panel_votes":          panel["panel_votes"],
            "saved_at":             datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        merged = apply_hooks(merged, skills)
        final_findings.append(merged)

    # 5. Store everything — append-only, no suppression
    await asyncio.gather(*[save_finding(f, run_id) for f in final_findings])

    # 6. Run summary
    by_risk = {}
    by_control = {}
    zero_tol_breaches = []

    for f in final_findings:
        level = f.get("risk_level", "UNKNOWN")
        control = f.get("soc2_control", "UNKNOWN")
        by_risk[level] = by_risk.get(level, 0) + 1
        by_control[control] = by_control.get(control, 0) + 1
        if f.get("zero_tolerance"):
            zero_tol_breaches.append(f.get("evidence_id"))

    summary = {
        "run_id":               run_id,
        "total_findings":       len(final_findings),
        "panel_confirmed":      sum(1 for f in final_findings if f["panel_verdict"] == "CONFIRMED"),
        "panel_dismissed":      sum(1 for f in final_findings if f["panel_verdict"] == "DISMISSED"),
        "by_risk":              by_risk,
        "by_soc2_control":      by_control,
        "zero_tolerance_breaches": zero_tol_breaches,
        "skills_active":        skills_summary(skills),
        "findings": [
            {
                "evidence_id":        f.get("evidence_id"),
                "type":               f.get("type"),
                "category":           f.get("category"),
                "resource":           f.get("resource"),
                "risk_level":         f.get("risk_level"),
                "soc2_control":       f.get("soc2_control"),
                "soc2_control_name":  f.get("soc2_control_name"),
                "panel_verdict":      f.get("panel_verdict"),
                "zero_tolerance":     f.get("zero_tolerance"),
                "impact":             f.get("impact"),
                "blast_radius":       f.get("blast_radius"),
                "affected_resources": f.get("affected_resources"),
                "remediation_steps":  f.get("remediation_steps"),
                "auditor_context":    f.get("auditor_context"),
                "auditor_evidence_needed": f.get("auditor_evidence_needed"),
                "due_date":           f.get("due_date"),
                "status":             f.get("status"),
            }
            for f in final_findings
        ],
    }

    await save_report(run_id, summary)
    if zero_tol_breaches:
        # Matches log-based metric filter: "zero-tolerance" — triggers Cloud Monitoring alert
        logger.warning(
            f"[argus] zero-tolerance breach detected run={run_id} "
            f"evidence_ids={zero_tol_breaches}"
        )
    logger.info(
        f"[argus] run={run_id} done — {len(final_findings)} findings, "
        f"{len(zero_tol_breaches)} zero-tolerance breaches"
    )
    return summary


@app.get("/findings")
async def list_findings(x_argus_secret: str | None = Header(default=None)):
    _verify(x_argus_secret)
    findings = await get_latest_findings(100)
    return {"count": len(findings), "findings": findings}


@app.get("/findings/open")
async def open_findings(x_argus_secret: str | None = Header(default=None)):
    _verify(x_argus_secret)
    findings = await get_open_findings()
    return {"count": len(findings), "findings": findings}


class ExceptionRequest(BaseModel):
    evidence_id: str
    finding_type: str
    resource: str
    accepted_by: str
    reason: str
    review_date: str  # ISO date — when this exception must be re-reviewed


@app.post("/exceptions")
async def register_exception(body: ExceptionRequest, x_argus_secret: str | None = Header(default=None)):
    """Register an accepted risk. Humans accept exceptions — never the panel."""
    _verify(x_argus_secret)
    doc_id = await save_exception(body.model_dump())
    logger.info(f"[argus] exception registered evidence_id={body.evidence_id} by={body.accepted_by}")
    return {"status": "registered", "exception_id": doc_id}


@app.get("/exceptions")
async def list_exceptions(x_argus_secret: str | None = Header(default=None)):
    _verify(x_argus_secret)
    from argus.store import get_exceptions
    exceptions = await get_exceptions()
    return {"count": len(exceptions), "exceptions": exceptions}


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    logger.error(f"[argus] unhandled: {exc}", exc_info=exc)
    return JSONResponse(status_code=500, content={"detail": str(exc)})
