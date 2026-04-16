#!/usr/bin/env bash
# Update Nuclei templates before starting the worker.
# If the bind-mount directory is empty (first run) this populates it.
# On subsequent starts it pulls only new/changed templates.
set -euo pipefail

TEMPLATES_DIR="${NUCLEI_TEMPLATES_DIR:-/templates}"

echo "[entrypoint] Updating Nuclei templates in ${TEMPLATES_DIR} ..."
nuclei -update-templates -ud "${TEMPLATES_DIR}" -silent 2>&1 || true

# Wait until the templates directory is populated (safety net for first run).
MAX_WAIT=120
WAITED=0
while [ -z "$(ls -A "${TEMPLATES_DIR}" 2>/dev/null)" ]; do
    if [ "$WAITED" -ge "$MAX_WAIT" ]; then
        echo "[entrypoint] ERROR: templates directory still empty after ${MAX_WAIT}s — aborting"
        exit 1
    fi
    echo "[entrypoint] Waiting for templates... (${WAITED}s / ${MAX_WAIT}s)"
    sleep 5
    WAITED=$((WAITED + 5))
done

echo "[entrypoint] Templates ready. Starting nuclei worker..."
exec python3 /app/worker.py
