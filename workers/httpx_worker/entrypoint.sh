#!/usr/bin/env bash
set -euo pipefail
echo "[entrypoint] HTTP worker starting..."
exec python3 /app/worker.py
