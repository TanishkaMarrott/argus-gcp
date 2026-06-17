#!/usr/bin/env bash
# Creates Cloud Scheduler job pointing at the deployed Cloud Run service.
# Usage: ./create_scheduler.sh <SERVICE_URL>
set -euo pipefail

SERVICE_URL="${1:?Usage: $0 <service_url>}"
PROJECT_ID="${GCP_PROJECT_ID:-$(gcloud config get-value project)}"
REGION="${GCP_REGION:-us-central1}"

# Get secret value
ARGUS_SECRET_VALUE=$(gcloud secrets versions access latest \
  --secret=argus-secret --project="$PROJECT_ID")

echo "==> Creating Cloud Scheduler job..."
gcloud scheduler jobs create http argus-weekly-audit \
  --project="$PROJECT_ID" \
  --location="$REGION" \
  --schedule="0 9 * * 1" \
  --uri="${SERVICE_URL}/audit" \
  --http-method=POST \
  --headers="X-Argus-Secret=${ARGUS_SECRET_VALUE},Content-Type=application/json" \
  --message-body="{}" \
  --time-zone="UTC" \
  --description="Argus weekly IAM and database security audit" \
  --attempt-deadline=30m 2>/dev/null || \
gcloud scheduler jobs update http argus-weekly-audit \
  --project="$PROJECT_ID" \
  --location="$REGION" \
  --schedule="0 9 * * 1" \
  --uri="${SERVICE_URL}/audit" \
  --http-method=POST \
  --headers="X-Argus-Secret=${ARGUS_SECRET_VALUE},Content-Type=application/json" \
  --message-body="{}" \
  --time-zone="UTC" \
  --attempt-deadline=30m

echo "==> Scheduler job created. Runs every Monday 09:00 UTC."
echo "==> To trigger manually:"
echo "    gcloud scheduler jobs run argus-weekly-audit --project=$PROJECT_ID --location=$REGION"
