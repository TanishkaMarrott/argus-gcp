#!/usr/bin/env bash
# Argus infra setup — run once before first deploy.
# Creates Secret Manager secret, Cloud Scheduler job.
set -euo pipefail

PROJECT_ID="${GCP_PROJECT_ID:-$(gcloud config get-value project)}"
REGION="${GCP_REGION:-us-central1}"
SERVICE_NAME="argus-auditor"
ARGUS_SECRET_VALUE="${ARGUS_SECRET:-$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')}"

echo "==> Project: $PROJECT_ID | Region: $REGION"

# Secret Manager
echo "==> Creating ARGUS_SECRET in Secret Manager..."
echo -n "$ARGUS_SECRET_VALUE" | \
  gcloud secrets create argus-secret \
    --project="$PROJECT_ID" \
    --data-file=- \
    --replication-policy=automatic 2>/dev/null || \
  echo -n "$ARGUS_SECRET_VALUE" | \
  gcloud secrets versions add argus-secret --project="$PROJECT_ID" --data-file=-

echo "   Secret value (save this): $ARGUS_SECRET_VALUE"

# Cloud Scheduler — triggers weekly audit every Monday 09:00 UTC
# Created after Cloud Run deploy so we have the service URL.
echo "==> Cloud Scheduler job will be created after deploy (needs service URL)."
echo "    Run: infra/create_scheduler.sh <SERVICE_URL>"

echo "==> Infra setup complete."
