# Spec: Smarter Nuclei Scanning

**Date:** 2026-04-18  
**Status:** Approved

## Goal

Make nuclei scans more targeted and effective in two ways:

1. **Expand template categories** (Part B) — expose `exposures`, `takeovers`, `default-logins`, and `misconfiguration` as selectable template categories. Immediate value, minimal code change.
2. **Tech-aware template routing** (Part A) — detect the technology stack running on each endpoint and automatically add relevant nuclei templates. Add API path detection to auto-tag REST/GraphQL endpoints.

## Part B — Expanded Template Categories

### Change

Add four new entries to `_DEFAULT_ALLOWED_NUCLEI_TEMPLATES` in `ingestor/app.py`:

```python
_DEFAULT_ALLOWED_NUCLEI_TEMPLATES = {
    "all",
    "http",
    "network",
    "dns",
    "ssl",
    "exposures",           # new
    "takeovers",           # new
    "default-logins",      # new
    "misconfiguration",    # new
}
```

These map directly to nuclei template directory names and work with the existing `-t <template_path>` resolution logic in `worker-naabu`. No other code changes required for Part B.

### UI Impact

The four new options appear immediately in the target create/edit form's nuclei template selector.

---

## Part A — Tech-Aware Template Routing

### Data Model Change

Add one column to `endpoints`:

```sql
ALTER TABLE endpoints ADD COLUMN technologies TEXT;
```

Value: JSON array of lowercase technology tags as returned by httpx, e.g. `["wordpress","php","apache"]`. Null when httpx returns no tech data or when the endpoint was discovered before this feature.

### httpx Worker Changes

Parse the `tech` (or `technologies`) field from httpx JSONL output and store it:

```python
technologies = json.dumps(event.get("tech") or [])
# store in endpoints row on upsert
```

Update the `endpoints` upsert to include `technologies` in both INSERT and UPDATE paths.

### Nuclei Worker Changes

#### 1. Tech-to-Template Mapping

Static dict in `workers/nuclei/worker.py`:

```python
TECH_TEMPLATE_MAP = {
    "wordpress":   ["cms/wordpress"],
    "drupal":      ["cms/drupal"],
    "joomla":      ["cms/joomla"],
    "apache":      ["misconfiguration/apache"],
    "nginx":       ["misconfiguration/nginx"],
    "iis":         ["misconfiguration/iis"],
    "php":         ["vulnerabilities/php"],
    "spring":      ["vulnerabilities/spring"],
    "laravel":     ["vulnerabilities/laravel"],
    "tomcat":      ["misconfiguration/tomcat"],
    "jenkins":     ["default-logins/jenkins", "exposures/jenkins"],
    "gitlab":      ["default-logins/gitlab"],
    "grafana":     ["default-logins/grafana", "exposures/grafana"],
    "elastic":     ["exposures/elastic"],
    "kibana":      ["exposures/kibana"],
    "jira":        ["default-logins/jira"],
    "confluence":  ["default-logins/confluence"],
}
```

This list is intentionally conservative — only mappings with high template coverage in the nuclei community repo.

#### 2. API Path Detection

Before building the nuclei command, inspect the URL path:

```python
API_PATH_PATTERNS = ["/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql", "/gql"]

def _is_api_endpoint(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(p in path for p in API_PATH_PATTERNS)
```

When `_is_api_endpoint` returns true, append `-tags api` to the nuclei command args.

#### 3. Command Construction

Modify `_scan_group` to accept per-URL technology data and build augmented template lists:

```
base templates:    [template_path]          (existing per-target config)
tech templates:    [cms/wordpress, ...]     (from TECH_TEMPLATE_MAP lookup)
api tags:          -tags api                (when URL matches API patterns)
```

All template paths are appended as additional `-t` flags. The `-tags api` flag is appended as a separate arg. If nuclei doesn't find templates at a given path it logs a warning and continues — no crash.

#### 4. Batch Grouping Change

Currently batches are grouped by `(scope_root, nuclei_template)`. With tech-aware routing, URLs in the same batch may need different extra templates. Two options:

- **Preferred:** keep batching by `(scope_root, nuclei_template)` but pass the union of all tech templates for the batch. Slightly over-scans but keeps batch efficiency.
- **Alternative:** group by `(scope_root, nuclei_template, frozenset(tech_templates))` for precision at the cost of smaller batches.

Use the preferred (union) approach for v1 of this feature.

### Where Technologies Are Loaded

In `_scan_group`, before building the command, load technologies for the batch from SQLite:

```python
endpoint_ids = [t["endpoint_id"] for t in group]
rows = conn.execute(
    f"SELECT technologies FROM endpoints WHERE id IN ({placeholders})",
    endpoint_ids
).fetchall()
tech_tags = set()
for row in rows:
    if row["technologies"]:
        for t in json.loads(row["technologies"]):
            tech_tags.update(TECH_TEMPLATE_MAP.get(t.lower(), []))
```

---

## Combined Effect

For an endpoint `https://blog.example.com/wp-login.php` running WordPress + PHP:

- Base template: `http` (per-target config)
- Tech templates added: `cms/wordpress`, `vulnerabilities/php`
- API tags: none (path is not an API path)

For `https://api.example.com/v2/users`:

- Base template: `http`
- Tech templates: whatever httpx detected
- API tags: `-tags api` (path matches `/v2/`)

---

## Configuration

No new env vars required. The `TECH_TEMPLATE_MAP` dict is hardcoded in the worker but structured so it can be extracted to a config file in a future iteration.

## Out of Scope

- Dynamic template map loaded from file/DB (future).
- Nuclei fuzzing mode (`-fuzz`) — too aggressive for Pi 5.
- Per-technology severity overrides.
- Automatic `ALLOWED_NUCLEI_TEMPLATES` expansion based on detected tech (keep the explicit allowlist).
