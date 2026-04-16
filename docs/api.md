# API Reference

The ingestor exposes a REST API over HTTP on port `8090` (configurable via `INGESTOR_PORT`). All request and response bodies are JSON. No authentication is implemented in v1 — restrict access at the network level.

**Base URL:** `http://<pi-ip>:8090`

---

## POST /targets

Add a new target to monitor, or re-enable a previously disabled target.

On success, the target is immediately enqueued for subdomain discovery.

### Request

```
POST /targets
Content-Type: application/json
```

| Field | Type | Required | Description |
|---|---|---|---|
| `scope_root` | string | Yes | The root domain to monitor, e.g. `example.com`. Must be a valid public domain — bare IPs, single-label names, and malformed strings are rejected. Normalized to lowercase on ingest. |
| `notes` | string | No | Optional free-text notes stored alongside the target. |

#### Validation rules for `scope_root`

The ingestor validates the domain against a strict regex before accepting it. Accepted formats:
- `example.com`
- `sub.example.com`
- `example.co.uk`

Rejected:
- Bare IP addresses (`192.168.1.1`)
- Single labels (`localhost`, `example`)
- Values with trailing dots, leading hyphens, or empty labels

### Response — 201 Created

```json
{
  "id": 1,
  "scope_root": "example.com",
  "queued": true
}
```

| Field | Type | Description |
|---|---|---|
| `id` | integer | `targets.id` of the created or re-enabled row |
| `scope_root` | string | Normalized domain as stored |
| `queued` | boolean | `true` if a `recon_domain` task was successfully enqueued; `false` if the inflight dedup key was already set (target was recently queued) |

### Response — 422 Unprocessable Entity

Returned when `scope_root` fails validation.

```json
{
  "detail": [
    {
      "loc": ["body", "scope_root"],
      "msg": "invalid domain",
      "type": "value_error"
    }
  ]
}
```

### Example

```bash
curl -X POST http://192.168.1.191:8090/targets \
  -H 'Content-Type: application/json' \
  -d '{"scope_root": "example.com", "notes": "bug bounty program"}'
```

---

## GET /targets

List all targets with summary statistics.

### Request

```
GET /targets
```

No parameters.

### Response — 200 OK

Array of target objects.

```json
[
  {
    "id": 1,
    "scope_root": "example.com",
    "enabled": 1,
    "created_at": "2024-01-15T10:30:00",
    "notes": "bug bounty program",
    "subdomain_count": 42,
    "last_recon_at": "2024-01-16T08:00:00"
  }
]
```

| Field | Type | Description |
|---|---|---|
| `id` | integer | Target ID |
| `scope_root` | string | Root domain |
| `enabled` | integer | `1` = active, `0` = disabled |
| `created_at` | string | ISO-8601 creation timestamp |
| `notes` | string or null | Operator notes |
| `subdomain_count` | integer | Number of subdomains currently in the DB for this target |
| `last_recon_at` | string or null | `finished_at` of the most recent successful `recon_domain` job |

### Example

```bash
curl http://192.168.1.191:8090/targets
```

---

## DELETE /targets/{target_id}

Disable a target. The target's data (subdomains, endpoints, findings) is retained. The target will no longer be included in refresh scheduling.

### Request

```
DELETE /targets/{target_id}
```

| Parameter | Location | Type | Description |
|---|---|---|---|
| `target_id` | path | integer | The `id` of the target to disable |

### Response — 200 OK

```json
{
  "disabled": 1
}
```

| Field | Type | Description |
|---|---|---|
| `disabled` | integer | Always `1` if the target was found and disabled |

### Response — 404 Not Found

```json
{
  "detail": "target not found"
}
```

### Example

```bash
curl -X DELETE http://192.168.1.191:8090/targets/1
```

---

## GET /targets/{target_id}/jobs

Retrieve recent jobs for a specific target.

### Request

```
GET /targets/{target_id}/jobs?limit=20
```

| Parameter | Location | Type | Default | Max | Description |
|---|---|---|---|---|---|
| `target_id` | path | integer | — | — | Target ID |
| `limit` | query | integer | `20` | `100` | Maximum number of job rows to return, ordered by `created_at DESC` |

### Response — 200 OK

```json
[
  {
    "id": 55,
    "type": "recon_domain",
    "target_ref": "example.com",
    "status": "done",
    "created_at": "2024-01-16T08:00:00",
    "started_at": "2024-01-16T08:00:01",
    "finished_at": "2024-01-16T08:02:33",
    "retry_count": 0,
    "worker_name": "worker-recon",
    "raw_output_path": "/data/output/recon/example.com-subfinder-1705392001.txt"
  }
]
```

### Response — 404 Not Found

```json
{
  "detail": "target not found"
}
```

### Example

```bash
curl 'http://192.168.1.191:8090/targets/1/jobs?limit=10'
```

---

## GET /findings

List recent findings, optionally filtered by severity.

### Request

```
GET /findings?severity=high&limit=50
```

| Parameter | Location | Type | Default | Max | Description |
|---|---|---|---|---|---|
| `severity` | query | string | _(none)_ | — | Filter to a specific severity level. One of: `info`, `low`, `medium`, `high`, `critical`. If omitted, all severities are returned. |
| `limit` | query | integer | `50` | `500` | Maximum number of findings to return, ordered by `first_seen DESC` |

### Response — 200 OK

```json
[
  {
    "id": 12,
    "template_id": "CVE-2021-44228",
    "severity": "critical",
    "title": "Apache Log4j RCE",
    "matched_at": "https://api.example.com/search",
    "first_seen": "2024-01-16T09:15:00",
    "last_seen": "2024-01-16T09:15:00",
    "endpoint_url": "https://api.example.com/search",
    "scope_root": "example.com"
  }
]
```

| Field | Type | Description |
|---|---|---|
| `id` | integer | Finding ID |
| `template_id` | string | Nuclei template ID |
| `severity` | string | Severity level |
| `title` | string | Vulnerability title from template |
| `matched_at` | string | URL where the finding was confirmed |
| `first_seen` | string | ISO-8601 timestamp of first detection |
| `last_seen` | string | ISO-8601 timestamp of last confirmed detection |
| `endpoint_url` | string | Normalized URL from the `endpoints` table |
| `scope_root` | string | Root domain of the parent target |

### Example

```bash
# All findings
curl http://192.168.1.191:8090/findings

# Only critical findings
curl 'http://192.168.1.191:8090/findings?severity=critical&limit=100'
```

---

## GET /subdomains

List subdomains, optionally filtered by target.

### Request

```
GET /subdomains?target_id=1&limit=100
```

| Parameter | Location | Type | Default | Max | Description |
|---|---|---|---|---|---|
| `target_id` | query | integer | _(none)_ | — | If provided, return only subdomains for this target. If omitted, return subdomains for all targets. |
| `limit` | query | integer | `100` | `1000` | Maximum number of rows to return, ordered by `first_seen DESC` |

### Response — 200 OK

```json
[
  {
    "id": 7,
    "hostname": "api.example.com",
    "source": "subfinder",
    "first_seen": "2024-01-16T08:02:00",
    "last_seen": "2024-01-16T08:02:00",
    "status": "active",
    "target_id": 1,
    "scope_root": "example.com"
  }
]
```

### Example

```bash
# All subdomains for target 1
curl 'http://192.168.1.191:8090/subdomains?target_id=1'

# All subdomains across all targets
curl http://192.168.1.191:8090/subdomains
```

---

## GET /health

Liveness check endpoint. Returns `200 OK` as long as the ingestor process is running.

### Request

```
GET /health
```

### Response — 200 OK

```json
{
  "status": "ok"
}
```

### Example

```bash
curl http://192.168.1.191:8090/health
```

---

## Error Codes

| HTTP Status | When |
|---|---|
| `201 Created` | Target was successfully created or re-enabled |
| `200 OK` | All other successful requests |
| `404 Not Found` | `target_id` not found in `DELETE /targets/{target_id}` or `GET /targets/{target_id}/jobs` |
| `422 Unprocessable Entity` | Request body validation failure — missing required field, wrong type, or domain fails regex validation |
| `500 Internal Server Error` | Unexpected exception (DB error, Redis unreachable) — check ingestor logs |
