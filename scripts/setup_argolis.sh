#!/usr/bin/env bash
# ==============================================================================
# Linktic SGDA & Claims AI Portal — Argolis Provisioning & Cloud Run Deployer
# Target Project: jmaciasc (599979914124) | Account: admin@jmaciasc.altostrat.com
# Region: us-central1
# ==============================================================================
set -euo pipefail

PROJECT_ID="${GCP_PROJECT_ID:-jmaciasc}"
PROJECT_NUMBER="599979914124"
EXPECTED_ACCOUNT="admin@jmaciasc.altostrat.com"
REGION="${GCP_REGION:-us-central1}"
AR_REPO="linktic-devsecops"
SERVICE_NAME="linktic-sgda-portal"
IMAGE_URI="${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPO}/${SERVICE_NAME}:latest"

BOLD="\033[1m"
GREEN="\033[0;32m"
CYAN="\033[0;36m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
RESET="\033[0m"

echo -e "${BOLD}${CYAN}==============================================================================${RESET}"
echo -e "${BOLD}${CYAN}  Linktic DevSecOps Pipeline — Argolis Cloud Environment Setup (${PROJECT_ID})  ${RESET}"
echo -e "${BOLD}${CYAN}==============================================================================${RESET}"

# 1. Validate Active Account & Project
echo -e "\n${BOLD}[1/4] Validating GCP Identity & Project (${PROJECT_ID} / ${PROJECT_NUMBER})...${RESET}"
if gcloud auth list --filter="account:${EXPECTED_ACCOUNT}" --format='value(account)' --limit=1 --quiet 2>/dev/null | grep -qx "${EXPECTED_ACCOUNT}"; then
  export CLOUDSDK_CORE_ACCOUNT="${EXPECTED_ACCOUNT}"
fi
ACTIVE_ACCOUNT="$(gcloud auth list --filter=status:ACTIVE --format='value(account)' --limit=1 --quiet 2>/dev/null || true)"
if [[ -z "${ACTIVE_ACCOUNT}" ]]; then
  echo -e "${RED}ERROR: No active gcloud account found. Run: gcloud auth login${RESET}"
  exit 1
fi
echo -e "  ${GREEN}✔${RESET} Active Account : ${BOLD}${ACTIVE_ACCOUNT}${RESET}"

ACTUAL_PROJECT_NUM="$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)' --quiet)"
if [[ "${ACTUAL_PROJECT_NUM}" != "${PROJECT_NUMBER}" ]]; then
  echo -e "${YELLOW}  ! Warning: Project number ${ACTUAL_PROJECT_NUM} differs from expected ${PROJECT_NUMBER}${RESET}"
else
  echo -e "  ${GREEN}✔${RESET} Verified Project: ${BOLD}${PROJECT_ID}${RESET} (Project Number: ${BOLD}${ACTUAL_PROJECT_NUM}${RESET})"
fi

# 2. Enable Required GCP APIs
echo -e "\n${BOLD}[2/4] Ensuring Required Google Cloud Security & AI APIs are Enabled...${RESET}"
REQUIRED_APIS=(
  "run.googleapis.com"
  "cloudbuild.googleapis.com"
  "artifactregistry.googleapis.com"
  "containeranalysis.googleapis.com"
  "aiplatform.googleapis.com"
  "secretmanager.googleapis.com"
  "cloudtrace.googleapis.com"
  "logging.googleapis.com"
)

ENABLED_APIS="$(gcloud services list --enabled --project="${PROJECT_ID}" --format='value(config.name)' --limit=200 --quiet)"
MISSING_APIS=()
for api in "${REQUIRED_APIS[@]}"; do
  if echo "${ENABLED_APIS}" | grep -qx "${api}"; then
    echo -e "  ${GREEN}✔${RESET} API Enabled: ${api}"
  else
    MISSING_APIS+=("${api}")
  fi
done

if [[ ${#MISSING_APIS[@]} -gt 0 ]]; then
  echo -e "  ${YELLOW}Enabling missing APIs: ${MISSING_APIS[*]}...${RESET}"
  gcloud services enable "${MISSING_APIS[@]}" --project="${PROJECT_ID}" --quiet
  echo -e "  ${GREEN}✔${RESET} All required APIs enabled."
fi

# 3. Ensure Artifact Registry Repository Exists
echo -e "\n${BOLD}[3/4] Ensuring Artifact Registry Repository '${AR_REPO}' in ${REGION}...${RESET}"
if gcloud artifacts repositories describe "${AR_REPO}" --location="${REGION}" --project="${PROJECT_ID}" --format="json(name)" --quiet >/dev/null 2>&1; then
  echo -e "  ${GREEN}✔${RESET} Artifact Registry repository '${AR_REPO}' already exists in ${REGION}."
else
  echo -e "  Creating Artifact Registry docker repository '${AR_REPO}'..."
  gcloud artifacts repositories create "${AR_REPO}" \
    --repository-format=docker \
    --location="${REGION}" \
    --description="Linktic DevSecOps Demo Container Repository" \
    --project="${PROJECT_ID}" \
    --quiet
  echo -e "  ${GREEN}✔${RESET} Created repository: ${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPO}"
fi

# 4. Build Container via Cloud Build & Deploy to Cloud Run
echo -e "\n${BOLD}[4/4] Building & Deploying '${SERVICE_NAME}' to Cloud Run (${REGION})...${RESET}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

echo -e "  Submitting container build to Cloud Build: ${IMAGE_URI}"
gcloud builds submit "${REPO_ROOT}" \
  --tag="${IMAGE_URI}" \
  --project="${PROJECT_ID}" \
  --quiet

echo -e "  Deploying service '${SERVICE_NAME}' to Cloud Run (${REGION})..."
if gcloud run deploy "${SERVICE_NAME}" \
  --image="${IMAGE_URI}" \
  --region="${REGION}" \
  --project="${PROJECT_ID}" \
  --port=8080 \
  --set-env-vars="GCP_PROJECT_ID=${PROJECT_ID},GCP_PROJECT_NUMBER=${PROJECT_NUMBER},DEFAULT_SECURITY_MODE=v2-secure,MODEL_ARMOR_ENABLED=true" \
  --allow-unauthenticated \
  --quiet 2>/dev/null; then
  echo -e "  ${GREEN}✔${RESET} Deployed '${SERVICE_NAME}' with public access (--allow-unauthenticated)."
else
  echo -e "  ${YELLOW}! Org Policy DRS restricted allUsers; deploying with authenticated/no-invoker-iam-check...${RESET}"
  gcloud run deploy "${SERVICE_NAME}" \
    --image="${IMAGE_URI}" \
    --region="${REGION}" \
    --project="${PROJECT_ID}" \
    --port=8080 \
    --set-env-vars="GCP_PROJECT_ID=${PROJECT_ID},GCP_PROJECT_NUMBER=${PROJECT_NUMBER},DEFAULT_SECURITY_MODE=v2-secure,MODEL_ARMOR_ENABLED=true" \
    --no-invoker-iam-check \
    --quiet
  echo -e "  ${GREEN}✔${RESET} Deployed '${SERVICE_NAME}' (--no-invoker-iam-check per Argolis Org Policy)."
fi

SERVICE_URL="$(gcloud run services describe "${SERVICE_NAME}" --region="${REGION}" --project="${PROJECT_ID}" --format='value(status.url)' --quiet)"
echo -e "\n${BOLD}${GREEN}==============================================================================${RESET}"
echo -e "${BOLD}${GREEN}  ✔ DEPLOYMENT COMPLETE!${RESET}"
echo -e "  Live Cloud Run URL: ${BOLD}${CYAN}${SERVICE_URL}${RESET}"
echo -e "${BOLD}${GREEN}==============================================================================${RESET}"
