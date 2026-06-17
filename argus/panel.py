"""
Adversarial panel — 3 Gemini skeptics, each with a distinct lens.
All default refuted=True. Majority vote (2/3) required to confirm a finding.
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
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash-001")

vertexai.init(project=PROJECT_ID, location=LOCATION)


SKEPTIC_LENSES = [
    {
        "name": "exploitability",
        "system": (
            "You are a GCP security skeptic. Your job is to REFUTE security findings. "
            "Focus on: is this finding actually exploitable in a real-world scenario for this specific GCP project? "
            "Are there compensating controls that make it unexploitable? "
            "Default to refuted=true unless you are highly confident exploitation is realistic. "
            "Return JSON only: {\"refuted\": bool, \"reason\": str}"
        ),
    },
    {
        "name": "blast_radius",
        "system": (
            "You are a GCP security skeptic. Your job is to REFUTE security findings. "
            "Focus on: if this finding were exploited, is the blast radius actually significant? "
            "Could it be contained? Does it affect sensitive data or critical services? "
            "Default to refuted=true unless blast radius is clearly significant. "
            "Return JSON only: {\"refuted\": bool, \"reason\": str}"
        ),
    },
    {
        "name": "false_positive",
        "system": (
            "You are a GCP security skeptic. Your job is to REFUTE security findings. "
            "Focus on: is this a false positive? Expected configuration for CI/CD, dev environments, "
            "or known GCP service accounts? Cloud Build, Cloud Run agent, dataflow workers, etc.? "
            "Default to refuted=true if there is a plausible legitimate reason. "
            "Return JSON only: {\"refuted\": bool, \"reason\": str}"
        ),
    },
]


async def run_panel(finding: dict) -> dict:
    """Run 3 skeptic agents in parallel. 2/3 must confirm for finding to pass."""
    finding_text = json.dumps(finding, indent=2)
    prompt = (
        f"Evaluate this GCP security finding:\n\n{finding_text}\n\n"
        "Project: shri-radha-tm (personal project, no production workloads, single engineer).\n"
        "Apply your lens and return your verdict as JSON."
    )

    tasks = [_skeptic_vote(lens, prompt) for lens in SKEPTIC_LENSES]
    votes = await asyncio.gather(*tasks, return_exceptions=True)

    confirmed_count = 0
    panel_results = []
    for i, vote in enumerate(votes):
        lens_name = SKEPTIC_LENSES[i]["name"]
        if isinstance(vote, Exception):
            # Fail-closed: parse error = refuted
            logger.warning(f"[panel] {lens_name} vote failed: {vote}")
            panel_results.append({"lens": lens_name, "refuted": True, "reason": f"error: {vote}"})
        else:
            panel_results.append({"lens": lens_name, **vote})
            if not vote.get("refuted", True):
                confirmed_count += 1

    confirmed = confirmed_count >= 2  # majority vote
    return {
        **finding,
        "panel_votes": panel_results,
        "panel_confirmed": confirmed,
        "panel_confirmed_count": confirmed_count,
    }


async def _skeptic_vote(lens: dict, prompt: str) -> dict:
    model = GenerativeModel(
        GEMINI_MODEL,
        system_instruction=lens["system"],
    )
    loop = asyncio.get_event_loop()
    response = await loop.run_in_executor(
        None,
        lambda: model.generate_content(prompt),
    )
    text = response.text.strip()
    # Strip markdown fences if present
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
        text = text.strip()
    return json.loads(text)
