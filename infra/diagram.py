"""Generate Argus architecture diagram — top-down, wide layout."""

from diagrams import Cluster, Diagram, Edge
from diagrams.gcp.compute import Run
from diagrams.gcp.database import Firestore
from diagrams.gcp.devtools import Scheduler
from diagrams.gcp.ml import AIPlatform
from diagrams.gcp.operations import Logging, Monitoring
from diagrams.gcp.security import Iam, KeyManagementService
from diagrams.gcp.storage import GCS

graph_attr = {
    "fontsize":  "20",
    "bgcolor":   "#F8FAFC",
    "pad":       "1.5",
    "splines":   "ortho",
    "nodesep":   "0.6",
    "ranksep":   "1.5",
    "fontname":  "Helvetica",
    "size":      "28,18",
    "dpi":       "180",
}

node_attr = {
    "fontsize": "12",
    "fontname": "Helvetica",
}

cluster_attr_blue   = {"bgcolor": "#E3F2FD", "fontsize": "13", "fontname": "Helvetica Bold"}
cluster_attr_green  = {"bgcolor": "#E8F5E9", "fontsize": "13", "fontname": "Helvetica Bold"}
cluster_attr_orange = {"bgcolor": "#FFF3E0", "fontsize": "13", "fontname": "Helvetica Bold"}
cluster_attr_purple = {"bgcolor": "#F3E5F5", "fontsize": "13", "fontname": "Helvetica Bold"}
cluster_attr_grey   = {"bgcolor": "#ECEFF1", "fontsize": "13", "fontname": "Helvetica Bold"}

with Diagram(
    "Argus — GCP IAM & Database Security Auditor",
    filename="/Users/tanishkamarrott/Downloads/argus-gcp/argus_architecture",
    outformat="png",
    show=False,
    direction="LR",
    graph_attr=graph_attr,
    node_attr=node_attr,
):

    # ── Trigger ───────────────────────────────────────────────
    with Cluster("Trigger Layer", graph_attr=cluster_attr_grey):
        scheduler = Scheduler("Cloud Scheduler\ndaily · 09:00 UTC\n0 9 * * *")

    # ── Skills ────────────────────────────────────────────────
    with Cluster("Skills Layer", graph_attr=cluster_attr_green):
        skills = GCS("skills/\ncc6_iam · cc6_network · a1_availability\n(SOC 2 controls, SLAs, evidence requirements)")

    # ── Core service ──────────────────────────────────────────
    with Cluster("argus-auditor  ·  Cloud Run  ·  us-central1", graph_attr=cluster_attr_blue):

        with Cluster("Step 1 — Collect  (rule-based, no LLM)", graph_attr={"bgcolor": "#BBDEFB"}):
            collector = Iam("Collector\nCloud Asset Inventory  +  IAM API\nIAM bindings · stale keys · Cloud SQL configs")

        with Cluster("Step 2 — Parallel Intelligence  (Gemini 2.5 Flash)", graph_attr={"bgcolor": "#BBDEFB"}):
            panel = AIPlatform("Adversarial Panel\n3 skeptic agents in parallel\nexploitability · blast_radius · false_positive\nmajority vote → verdict label")
            remediator = AIPlatform("Remediator\nruns on ALL findings\nimpact · blast_radius · affected_resources\nremediation steps · auditor context")

        with Cluster("Step 3 — Deterministic Hooks  (no LLM)", graph_attr={"bgcolor": "#BBDEFB"}):
            hooks = KeyManagementService("Hooks\nSOC 2 control map (CC6.1 · CC6.3 · CC6.6 · CC6.7 · A1.2)\nEvidence ID · SLA due date · zero-tolerance flag\nstatus = OPEN  (humans close, never the panel)")

    # ── Storage ───────────────────────────────────────────────
    with Cluster("Storage Layer  ·  Firestore", graph_attr=cluster_attr_orange):
        findings  = Firestore("argus_findings\nappend-only evidence log")
        reports   = Firestore("argus_reports\nrun summaries")
        exceptions = Firestore("argus_exceptions\naccepted risk register\nPOST /exceptions")

    # ── Observability ─────────────────────────────────────────
    with Cluster("Observability", graph_attr=cluster_attr_purple):
        cloud_log   = Logging("Cloud Logging\nlog-based metric:\nargus_zero_tolerance_breach")
        monitoring  = Monitoring("Cloud Monitoring\nalert policy:\nZero-Tolerance SOC2 Breach")

    # ── SOC 2 output ──────────────────────────────────────────
    with Cluster("SOC 2 Type II Evidence Output", graph_attr=cluster_attr_green):
        soc2 = GCS("Structured evidence per finding\nControl mapping · Due dates\nRemediation commands · Auditor context")

    # ── Flows ─────────────────────────────────────────────────
    scheduler >> Edge(label="POST /audit", color="#1565C0", fontsize="11") >> collector
    skills    >> Edge(label="load controls + SLAs", style="dashed", color="#2E7D32", fontsize="11") >> collector

    collector >> Edge(label="raw findings", color="#1565C0", fontsize="11") >> panel
    collector >> Edge(label="raw findings", color="#1565C0", fontsize="11") >> remediator

    panel     >> Edge(label="verdict (CONFIRMED / DISMISSED)", color="#6A1B9A", fontsize="11") >> hooks
    remediator >> Edge(label="impact · blast_radius · remediation", color="#E65100", fontsize="11") >> hooks

    exceptions >> Edge(label="accepted risk check", style="dashed", color="#BF360C", fontsize="11") >> hooks

    hooks >> Edge(label="evidence record", color="#E65100", fontsize="11") >> findings
    hooks >> Edge(label="run summary", style="dashed", color="#E65100", fontsize="11") >> reports

    findings  >> Edge(label="structured evidence", color="#2E7D32", fontsize="11") >> soc2
    reports   >> Edge(style="dashed", color="#2E7D32", fontsize="11") >> soc2

    collector >> Edge(style="dashed", color="#9E9E9E", fontsize="10") >> cloud_log
    panel     >> Edge(style="dashed", color="#9E9E9E", fontsize="10") >> cloud_log
    cloud_log >> Edge(style="dashed", color="#9E9E9E", fontsize="10") >> monitoring
