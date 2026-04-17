#!/usr/bin/env bash
# Polls master for new commits, pulls latest code, rebuilds images, and restarts containers.
# Run via cron: */2 * * * * /opt/recon-platform/repo/scripts/auto-deploy.sh

set -euo pipefail

LOG="/opt/recon-platform/logs/deploy.log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

# Check for new commits via GitHub API (no clone needed)
REMOTE_SHA=$(curl -sf "https://api.github.com/repos/Baroude/pi5-recon-platform/commits/master" \
  | jq -r '.sha')

LAST_SHA_FILE="/opt/recon-platform/config/.last_deployed_sha"
LAST_SHA=$(cat "$LAST_SHA_FILE" 2>/dev/null || echo "")

if [ "$REMOTE_SHA" = "$LAST_SHA" ]; then
  exit 0
fi

log "New commit: ${LAST_SHA:-none} → ${REMOTE_SHA}"

# Pull latest code and rebuild images
REPO_DIR="/opt/recon-platform/repo"
log "Pulling latest code..."
git -C "$REPO_DIR" pull --ff-only origin master

log "Rebuilding images..."
CACHE_BUST="${REMOTE_SHA}" docker compose -f "$REPO_DIR/docker-compose.yml" -p recon-platform build --pull

log "Restarting containers..."
CACHE_BUST="${REMOTE_SHA}" docker compose -f "$REPO_DIR/docker-compose.yml" -p recon-platform up -d

echo "${REMOTE_SHA}" > "$LAST_SHA_FILE"
log "Deploy complete. Stack updated to ${REMOTE_SHA}"
