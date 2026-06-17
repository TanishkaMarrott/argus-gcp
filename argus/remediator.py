"""
Remediator — runs on ALL findings regardless of panel verdict.
Generates: risk_level, impact, blast_radius, affected_resources,
           remediation_steps, auditor_evidence_context.
"""

import asyncio
import json
import logging
import os

import vertexai
from vertexai.generative_models import GenerativeModel

logger = logging.getLogger(__name__)

PROJECT_ID = os.environ.get("PROJECT_ID", "shri-radha-tm")
LOCATION = os.environ.get("REGION", "us-central1")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")

vertexai.init(project=PROJECT_ID, location=LOCATION)

SYSTEM_PROMPT = """You are a GCP security engineer preparing evidence for a SOC 2 Type II audit.

Given a GCP security finding, produce a thorough analysis regardless of project size:

1. risk_level: HIGH / MEDIUM / LOW
2. impact: What an attacker gains or what fails if unresolved. Specific, max 3 sentences.
3. blast_radius: Which systems, data, or users are at risk if this is exploited.
4. affected_resources: Concrete list of GCP resources put at risk.
5. remediation_steps: Exact step-by-step gcloud CLI commands using the actual resource names from the finding.
   Include a verification step. Prefer least-privilege replacements over outright removal.
6. auditor_context: One sentence explaining why this matters for SOC 2 compliance.

Return JSON only — no markdown fences:
{
  "risk_level": "HIGH|MEDIUM|LOW",
  "impact": "string",
  "blast_radius": "string",
  "affected_resources": ["string"],
  "remediation_steps": [
    {"step": 1, "description": "string", "command": "gcloud ... (exact)"}
  ],
  "auditor_context": "string"
}"""


async def remediate(finding: dict) -> dict:
    finding_text = json.dumps(
        {k: v for k, v in finding.items() if k not in ("panel_votes",)},
        indent=2,
    )
    prompt = (
        f"GCP project: {PROJECT_ID}\n\n"
        f"Security finding:\n{finding_text}\n\n"
        "Produce full security analysis and remediation."
    )

    model = GenerativeModel(GEMINI_MODEL, system_instruction=SYSTEM_PROMPT)
    loop = asyncio.get_event_loop()

    try:
        response = await loop.run_in_executor(
            None, lambda: model.generate_content(prompt)
        )
        text = response.text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])
        result = json.loads(text)
    except Exception as e:
        logger.error(f"[remediator] failed for {finding.get('type')}: {e}")
        result = {
            "risk_level":          finding.get("severity_hint", "MEDIUM"),
            "impact":              "Manual review required — remediator could not generate analysis.",
            "blast_radius":        "Unknown — review finding manually.",
            "affected_resources":  [finding.get("resource", "unknown")],
            "remediation_steps":   [{"step": 1, "description": "Manual review required", "command": ""}],
            "auditor_context":     "This finding requires manual triage before SOC 2 evidence can be collected.",
        }

    return {**finding, **result}
