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
    "$BASE/wordlists"
)

echo "Creating recon-platform directories under $BASE ..."
for d in "${DIRS[@]}"; do
    mkdir -p "$d"
    echo "  $d"
done

# Ensure Docker containers (running as root) can write to these paths.
chmod -R 755 "$BASE"

# ---------------------------------------------------------------------------
# Wordlists — dns-small is downloaded automatically; medium/large are opt-in.
# ---------------------------------------------------------------------------
SECLISTS="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS"

if [ ! -f "$BASE/wordlists/dns-small.txt" ]; then
    echo "Downloading dns-small.txt (~20K words)..."
    curl -sL "$SECLISTS/subdomains-top1million-20000.txt" \
         -o "$BASE/wordlists/dns-small.txt"
    echo "  $BASE/wordlists/dns-small.txt"
fi

if [ ! -f "$BASE/wordlists/dns-medium.txt" ]; then
    echo "[wordlists] dns-medium.txt not present — run to download:"
    echo "  curl -sL $SECLISTS/subdomains-top1million-110000.txt -o $BASE/wordlists/dns-medium.txt"
fi

if [ ! -f "$BASE/wordlists/dns-large.txt" ]; then
    echo "[wordlists] dns-large.txt not present — run to download:"
    echo "  curl -sL $SECLISTS/subdomains-top1million.txt -o $BASE/wordlists/dns-large.txt"
fi

# ---------------------------------------------------------------------------
# Unbound root.hints — download or refresh if older than 30 days.
# ---------------------------------------------------------------------------
HINTS="$BASE/config/unbound/root.hints"
mkdir -p "$BASE/config/unbound"
if [ ! -f "$HINTS" ] || find "$HINTS" -mtime +30 -print | grep -q .; then
    echo "Refreshing root.hints from internic.net..."
    curl -sL https://www.internic.net/domain/named.cache -o "$HINTS"
    echo "  $HINTS"
fi

echo ""
echo "Done. Next steps:"
echo "  1. Copy .env.example to $BASE/config/.env and fill in secrets."
echo "  2. In Portainer: Stacks → Add stack → paste docker-compose.yml."
echo "  3. Set the stack's env file to $BASE/config/.env  (or paste vars inline)."
echo "  4. Deploy."
