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

# Write amass datasources config only when AMASS_SHODAN_API_KEY is provided.
if [ -n "${AMASS_SHODAN_API_KEY:-}" ]; then
    AMASS_CFG_DIR="/root/.config/amass"
    mkdir -p "$AMASS_CFG_DIR"
    cat > "$AMASS_CFG_DIR/datasources.yaml" <<EOF
datasources:
  - name: Shodan
    creds:
      - apikey: ${AMASS_SHODAN_API_KEY}
EOF
    echo "[entrypoint] Amass datasources config written to $AMASS_CFG_DIR/datasources.yaml"
fi

exec python3 /app/worker.py
