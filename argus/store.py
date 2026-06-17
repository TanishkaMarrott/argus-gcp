"""
Firestore store — append-only evidence log.
Findings are never overwritten. Each run creates new documents.
Evidence IDs are stable across runs for the same resource+type.
"""

import datetime
import logging
import os

from google.cloud import firestore

logger = logging.getLogger(__name__)

PROJECT_ID = os.environ.get("PROJECT_ID", "shri-radha-tm")
_db: firestore.AsyncClient | None = None


def _client() -> firestore.AsyncClient:
    global _db
    if _db is None:
        _db = firestore.AsyncClient(project=PROJECT_ID)
    return _db


async def save_finding(finding: dict, run_id: str) -> str:
    """Append-only — each run writes a new document. Never overwrites."""
    db = _client()
    evidence_id = finding.get("evidence_id", "EVD-UNKNOWN")
    # Key by evidence_id + run_id so same finding in multiple runs = multiple records
    doc_id = f"{evidence_id}_{run_id}"
    doc = {
        **finding,
        "run_id":   run_id,
        "saved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "project":  PROJECT_ID,
    }
    # set() not merge — each run's record is independent
    await db.collection("argus_findings").document(doc_id).set(doc)
    return doc_id


async def save_report(run_id: str, summary: dict) -> None:
    db = _client()
    await db.collection("argus_reports").document(run_id).set({
        **summary,
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "project":    PROJECT_ID,
    })


async def get_latest_findings(limit: int = 100) -> list[dict]:
    db = _client()
    results = []
    async for doc in (
        db.collection("argus_findings")
        .order_by("saved_at", direction=firestore.Query.DESCENDING)
        .limit(limit)
        .stream()
    ):
        results.append(doc.to_dict())
    return results


async def save_exception(exception: dict) -> str:
    """Write to argus_exceptions. Append-only — one doc per accepted risk."""
    db = _client()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    doc_id = f"EXC-{exception['evidence_id']}-{now[:10]}"
    await db.collection("argus_exceptions").document(doc_id).set({
        **exception,
        "registered_at": now,
        "project": PROJECT_ID,
        "status": "ACTIVE",
    })
    return doc_id


async def get_exceptions() -> list[dict]:
    db = _client()
    results = []
    async for doc in db.collection("argus_exceptions").order_by("registered_at").stream():
        results.append(doc.to_dict())
    return results


async def get_open_findings() -> list[dict]:
    """Return all findings with status=OPEN for remediation tracking."""
    db = _client()
    results = []
    async for doc in (
        db.collection("argus_findings")
        .where("status", "==", "OPEN")
        .order_by("due_date")
        .stream()
    ):
        results.append(doc.to_dict())
    return results
