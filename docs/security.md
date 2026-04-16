# Security

## Scope Enforcement

### Domain validation at ingest

Every target submitted via `POST /targets` is validated against a strict regex in the ingestor (`_DOMAIN_RE`) before any processing occurs. The regex rejects:

- Bare IP addresses (e.g. `192.168.1.1`)
- Single-label names (e.g. `localhost`, `example`)
- Values with leading hyphens, trailing dots, or empty labels

Only valid, multi-label public domain names are accepted.

### Subdomain scope filtering in the recon worker

The recon worker (`workers/recon/worker.py`) applies `is_in_scope(hostname, scope_root)` to every hostname returned by subfinder and amass before it is stored or enqueued. This function:

1. Normalizes both strings to lowercase.
2. Strips wildcard prefixes (`*.`) from returned hostnames.
3. Returns `True` only if the hostname **equals** `scope_root` or is a **proper subdomain** of it (i.e., ends with `.<scope_root>`).

Any hostname that is not a subdomain of the declared scope root — regardless of what subfinder or amass returns — is silently discarded. It is never stored in the DB and never enqueued for probing or scanning.

This means lateral expansion (e.g., a tool returning an unrelated domain) is structurally impossible; the scope check happens in code before anything downstream sees the result.

### No active Amass

Amass is run in passive mode only (`amass enum -passive`). Active DNS enumeration and brute-forcing are disabled in v1. Subfinder also runs in passive-only mode (no active probing flags).

---

## Input Validation

### Domain regex (ingestor)

The `TargetIn` Pydantic model validates `scope_root` with a regex that enforces:
- At least two labels separated by `.`
- Each label: 1–63 characters, alphanumeric or hyphen, no leading/trailing hyphens
- Total length ≤ 253 characters
- No IP addresses, no trailing dots, no underscores in labels

The value is also lowercased and stripped of whitespace before the regex is applied, so case variations and accidental whitespace are handled without error.

### Task payload validation in workers

Each worker validates its task payload before performing any work:

- `worker-recon`: checks `domain` is present and non-empty.
- `worker-httpx`: checks `hostname`, `target_id`, and `scope_root` are present; additionally confirms the subdomain exists in the DB under the declared `target_id`.
- `worker-nuclei`: checks `url` and `endpoint_id` are present.
- `worker-notify`: checks `notification_type` is one of the three known values; unknown types are logged and acked without processing.

Tasks that fail validation are acked (not retried), since retrying a structurally invalid payload is not useful. The malformed task is recorded in `failed_jobs`.

---

## Subprocess Safety

All external tool invocations use **list-form argument passing** — `subprocess.run([...])` — never string interpolation or `shell=True`. This eliminates shell injection vulnerabilities entirely: user-supplied values (domain names, URLs) are passed as positional arguments to the subprocess and are never interpreted by a shell.

Examples:

```python
# worker-recon (safe)
cmd = ["subfinder", "-d", domain, "-o", output_file, "-silent", ...]
subprocess.run(cmd, capture_output=True, text=True, timeout=120)

# worker-httpx (safe)
cmd = ["httpx", "-u", hostname, "-silent", "-json", "-o", output_file, ...]
subprocess.run(cmd, capture_output=True, text=True, timeout=120)

# worker-nuclei (safe)
cmd = ["nuclei", "-u", url, "-t", templates_dir, "-severity", severity_str, ...]
subprocess.run(cmd, capture_output=True, text=True, timeout=300)
```

The severity string passed to nuclei (`medium,high,critical`) is built programmatically from a whitelist of known values, not from raw user input. The domain, hostname, and URL values come from the DB after scope-check filtering, not directly from external input.

---

## Network Isolation

### Internal network

All containers communicate over the `recon-net` Docker bridge network. Containers are not reachable from outside Docker on this network. Redis, in particular, has no host port binding and is only accessible to containers on `recon-net`.

### Exposed ports

Only one port is exposed to the host:

| Container | Host port | Container port |
|---|---|---|
| ingestor | `8090` | `8090` |

The ingestor API has no authentication. It should not be exposed to the public internet. Restrict access using:
- A firewall rule on the Pi (`ufw deny 8090` then allow from trusted IPs only)
- A reverse proxy with basic auth or IP allowlist

### Outbound traffic

Workers make outbound connections to:
- Passive DNS APIs (subfinder, amass providers)
- The target hostnames (httpx probing and nuclei scanning)
- Telegram / Discord APIs (notify worker)
- `nuclei.projectdiscovery.io` (template updates)

No outbound connections are made by Redis, ingestor, or the SQLite layer.

---

## Secrets Management

### Production: Portainer environment injection

In production, all secrets (API keys, Telegram token, Discord webhook) are injected as environment variables via Portainer's stack environment editor. They are stored in Portainer's internal database, which is encrypted at rest. They are never written to disk on the Pi, never appear in Docker image layers, and never appear in the git repository.

### Development: .env file

A `.env.example` file is provided in the repository with placeholder values. Copy it to `.env` and populate it for local `docker compose` use. The `.env` file is listed in `.gitignore` and must never be committed.

### No secrets in images

None of the Dockerfiles copy or embed any secret values. All environment-dependent configuration is read at runtime via `os.environ.get()`. Building the images does not require any secrets.

### Subfinder provider config

The recon worker writes subfinder's provider configuration YAML file at container startup from environment variables (in `entrypoint.sh`). This file exists only inside the container's ephemeral filesystem and is not persisted to any bind mount. It is recreated on every container start.

---

## Additional Notes

### No shell=True, no f-string commands

A code-level policy is enforced: no `subprocess` call uses `shell=True`, and no command string is constructed by interpolating user data. This protects against command injection even if validation were bypassed.

### SQLite injection prevention

All database queries use parameterized statements (Python's `sqlite3` parameter binding with `?` placeholders). No SQL is constructed by string interpolation.

### No RBAC in v1

There is no authentication, authorization, or multi-user support in v1. The API is single-tenant and trusts all callers on the network. Access control is entirely the responsibility of network-level restrictions (firewall, VPN, reverse proxy).

### Authorized use only

This platform is designed for authorized bug bounty and external attack-surface reconnaissance only. The scope enforcement model (domain validation + subdomain scope filtering) is a technical aid but does not substitute for operator responsibility. Only add targets you are authorized to scan.
