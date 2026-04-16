#!/usr/bin/env bash
# Write subfinder provider config from stack environment variables.
# Subfinder reads ~/.config/subfinder/provider-config.yaml by default.
set -euo pipefail

CFG_DIR="/root/.config/subfinder"
mkdir -p "$CFG_DIR"
: > "$CFG_DIR/provider-config.yaml"   # truncate / create

add_key() {
    local provider="$1"
    local value="$2"
    if [ -n "$value" ]; then
        printf "%s:\n  - %s\n" "$provider" "$value" >> "$CFG_DIR/provider-config.yaml"
    fi
}

add_key "shodan"          "${SUBFINDER_SHODAN_API_KEY:-}"
add_key "securitytrails"  "${SUBFINDER_SECURITYTRAILS_API_KEY:-}"
add_key "virustotal"      "${SUBFINDER_VIRUSTOTAL_API_KEY:-}"

if [ -n "${SUBFINDER_CENSYS_API_ID:-}" ] && [ -n "${SUBFINDER_CENSYS_API_SECRET:-}" ]; then
    add_key "censys" "${SUBFINDER_CENSYS_API_ID}:${SUBFINDER_CENSYS_API_SECRET}"
fi

echo "[entrypoint] Provider config written to $CFG_DIR/provider-config.yaml"
exec python3 /app/worker.py
