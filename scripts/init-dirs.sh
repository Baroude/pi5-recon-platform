#!/usr/bin/env bash
# =============================================================================
# init-dirs.sh — Run once on the Pi before deploying the Portainer stack.
# Creates bind-mount directories and sets ownership to the Docker user (root).
# =============================================================================
set -euo pipefail

BASE=/opt/recon-platform

DIRS=(
    "$BASE/data/db"
    "$BASE/data/output/recon"
    "$BASE/data/output/httpx"
    "$BASE/data/output/nuclei"
    "$BASE/data/redis"
    "$BASE/config"
    "$BASE/logs"
    "$BASE/nuclei-templates"
)

echo "Creating recon-platform directories under $BASE ..."
for d in "${DIRS[@]}"; do
    mkdir -p "$d"
    echo "  $d"
done

# Ensure Docker containers (running as root) can write to these paths.
chmod -R 755 "$BASE"

echo ""
echo "Done. Next steps:"
echo "  1. Copy .env.example to $BASE/config/.env and fill in secrets."
echo "  2. In Portainer: Stacks → Add stack → paste docker-compose.yml."
echo "  3. Set the stack's env file to $BASE/config/.env  (or paste vars inline)."
echo "  4. Deploy."
