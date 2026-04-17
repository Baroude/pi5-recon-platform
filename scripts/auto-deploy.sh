#!/usr/bin/env bash
# Polls master for new commits and triggers a Portainer git redeploy if changed.
# Run via cron: */2 * * * * /opt/recon-platform/scripts/auto-deploy.sh
#
# Required env vars (put in /opt/recon-platform/config/deploy.env):
#   PORTAINER_USERNAME, PORTAINER_PASSWORD, PORTAINER_STACK_NAME

set -euo pipefail

ENV_FILE="/opt/recon-platform/config/deploy.env"
LOG="/opt/recon-platform/logs/deploy.log"
PORTAINER_URL="http://localhost:9000"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

# Load credentials
# shellcheck source=/dev/null
source "$ENV_FILE"

# Check for new commits via GitHub API (no clone needed)
REMOTE_SHA=$(curl -sf "https://api.github.com/repos/Baroude/pi5-recon-platform/commits/master" \
  | jq -r '.sha')

LAST_SHA_FILE="/opt/recon-platform/config/.last_deployed_sha"
LAST_SHA=$(cat "$LAST_SHA_FILE" 2>/dev/null || echo "")

if [ "$REMOTE_SHA" = "$LAST_SHA" ]; then
  exit 0
fi

log "New commit: ${LAST_SHA:-none} → ${REMOTE_SHA}"

# Authenticate with Portainer
TOKEN=$(curl -sf -X POST "${PORTAINER_URL}/api/auth" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${PORTAINER_USERNAME}\",\"password\":\"${PORTAINER_PASSWORD}\"}" \
  | jq -r '.jwt')

# Find stack
STACK=$(curl -sf "${PORTAINER_URL}/api/stacks" \
  -H "Authorization: Bearer ${TOKEN}" \
  | jq -r --arg name "${PORTAINER_STACK_NAME}" '.[] | select(.Name == $name)')

STACK_ID=$(echo "${STACK}" | jq -r '.Id')
ENDPOINT_ID=$(echo "${STACK}" | jq -r '.EndpointId')

# Upsert CACHE_BUST, preserve all other env vars
UPDATED_ENV=$(echo "${STACK}" | jq -c \
  --arg cb "${REMOTE_SHA}" \
  '.Env | map(select(.name != "CACHE_BUST")) + [{"name":"CACHE_BUST","value":$cb}]')

# Trigger Portainer git redeploy
curl -sf -X PUT \
  "${PORTAINER_URL}/api/stacks/${STACK_ID}/git/redeploy?endpointId=${ENDPOINT_ID}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  --data-binary "{\"pullImage\":true,\"repositoryAuthentication\":false,\"env\":${UPDATED_ENV}}" \
  > /dev/null

echo "${REMOTE_SHA}" > "$LAST_SHA_FILE"
log "Portainer redeploy triggered. Stack: ${PORTAINER_STACK_NAME}"
