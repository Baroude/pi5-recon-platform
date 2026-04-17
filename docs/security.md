# Security

## Scope Control

### Target validation

`POST /targets` accepts only valid public domain roots.

Rejected examples:

- IP addresses
- single-label names
- malformed hostnames

### In-scope filtering

Workers enforce scope checks before persistence/enqueue:

- `worker-recon`: filters tool output to `scope_root` subtree
- `worker-dns-brute`: filters brute/permutation results to `scope_root` subtree
- `worker-httpx`: drops out-of-scope redirect targets
- `worker-nuclei`: skips out-of-scope endpoint hosts

## Active Recon Controls

Active DNS brute force is implemented, but gated:

- disabled by default per target (`active_recon=false`)
- enabled explicitly via API (`PATCH /targets/{target_id}` or `POST /targets`)
- wordlist must be from allowlist (`dns-small.txt`, `dns-medium.txt`, `dns-large.txt`)

`worker-dns-brute` also does wildcard detection to avoid noisy expansion.

## Command Execution Safety

All tool invocations use argument lists (`subprocess.run([...])` / `Popen([...])`), not `shell=True`.

This prevents shell command injection from task data.

## SQL Safety

SQLite operations use parameterized queries with placeholders.
No SQL string interpolation with user input.

## Network Isolation

- Internal communication only on `recon-net`
- Redis and resolver are not host-exposed
- Only ingestor exposes host port `8090`

API has no auth in v1. Restrict access at network edge (firewall/VPN/reverse proxy).

## Secrets Handling

- Production: inject via Portainer stack environment
- Local compose: use `.env` from `.env.example`
- Secrets are not embedded in images

## Outbound Traffic

Expected egress destinations:

- passive recon providers
- scanned targets (httpx/nuclei)
- Telegram/Discord APIs
- nuclei template update endpoints
- root hints download URL (init script)

## Operational Risks and Mitigations

- Queue growth: monitor `LLEN` and DLQ depth
- Notification rate limits: notify worker re-enqueues on HTTP 429 with retry-after sleep
- Resolver health: monitor `resolver` healthcheck and root-hints file integrity
