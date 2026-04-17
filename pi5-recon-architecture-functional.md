# Raspberry Pi 5 Recon Platform
## Architecture and Functional Specification

Version: 0.1  
Date: 2026-04-16  
Target host: Raspberry Pi 5 with Portainer and Docker

---

## 1. Purpose

This document defines the architecture and functional behavior for a self-hosted reconnaissance platform designed to run on a Raspberry Pi 5 under Docker and Portainer.

The platform is intended for:
- OSINT enrichment
- Passive asset discovery
- HTTP probing and fingerprinting
- Template-based vulnerability discovery
- Incremental, queue-driven automation for bug bounty and authorized external attack-surface workflows

This platform is **not** intended to defend the local home network. It is designed as a hosted offensive-research and automation stack for authorized targets.

---

## 2. Design Goals

### Primary goals
- Run reliably on a Raspberry Pi 5
- Be manageable through Portainer as a single stack
- Use a queue so tasks execute only when needed
- Avoid wasteful rescanning and reduce rate-limit pressure
- Support incremental growth from simple recon to a more capable automation platform
- Keep components replaceable and loosely coupled

### Non-goals
- Full enterprise attack-surface management
- Heavy GUI-driven analysis environments
- High-throughput mass scanning from a single Pi
- Internal network monitoring or IDS/SIEM functions

---

## 3. High-Level Architecture

```text
              +----------------------+
              |   User / Operator     |
              |  domain, scope input  |
              +----------+------------+
                         |
                         v
              +----------------------+
              |   API / Ingestor      |
              | add targets / jobs    |
              +----------+------------+
                         |
                         v
              +----------------------+
              |      Redis Queue      |
              | task broker + state   |
              +---+---------+---------+
                  |         |         |
                  |         |         |
                  v         v         v
         +-------------+ +-------------+ +-------------+
         | Recon Worker| | HTTP Worker | | Nuclei Worker|
         | subfinder   | | httpx       | | nuclei       |
         | amass       | |             | |              |
         +------+------+ +------+------+ +------+------+
                |               |                |
                +-------+-------+----------------+
                        |
                        v
              +----------------------+
              |   Result Storage      |
              | SQLite + JSON files   |
              +----------+------------+
                         |
             +-----------+-----------+
             |                       |
             v                       v
  +----------------------+   +----------------------+
  | Notification Worker  |   | Optional Web Viewer  |
  | Telegram / Discord   |   | simple dashboard/API |
  +----------------------+   +----------------------+
```

---

## 4. Core Architectural Principles

### 4.1 Event-driven execution
The system should create downstream tasks only when upstream stages discover something new.

Examples:
- A newly discovered subdomain creates an `http_probe` task.
- A new alive web endpoint creates a `nuclei_scan` task.
- A new high-severity result creates a `notify` task.

### 4.2 Incremental recon
The system should avoid rescanning unchanged assets as much as possible.

Examples:
- Already known subdomains should not be re-enqueued unless a refresh interval is reached.
- HTTP endpoints already probed recently should not be probed again immediately.
- Nuclei scans should prefer only new or changed live endpoints.

### 4.3 Rate control and ban reduction
The platform should use conservative concurrency and task pacing so it behaves predictably and reduces the chance of upstream API throttling or IP bans.

### 4.4 Replaceable workers
Each worker should be isolated and focused on one responsibility. Tools may be swapped later without changing the overall architecture.

---

## 5. Functional Scope

### Included in v1
- Manual target submission
- Queue-based job orchestration
- Passive subdomain discovery
- Optional low-volume Amass execution
- HTTP probing of discovered hosts
- Template-based vulnerability scanning on alive HTTP targets
- Persistent storage of findings and metadata
- Deduplication of tasks and findings
- Notification of important new results
- Portainer-friendly deployment

### Explicitly excluded in v1
- Automated screenshot capture
- JavaScript endpoint extraction
- Headless browser reconnaissance
- Complex multi-user RBAC
- Leak ingestion pipelines
- Full GUI case management

---

## 6. Components

### 6.1 Ingest / Scheduler
**Purpose:** Accept new targets and generate the first tasks.

**Responsibilities:**
- Accept a target domain from the operator
- Validate scope format
- Insert the target into storage
- Enqueue the initial recon job
- Optionally schedule periodic refresh jobs

**Inputs:**
- Domain or program scope root

**Outputs:**
- `recon_domain` queue tasks

**Implementation options:**
- Lightweight Python service with REST endpoint
- Simple CLI wrapper writing directly to Redis and SQLite
- Minimal cron scheduler for periodic refreshes

---

### 6.2 Redis Queue
**Purpose:** Hold work items and decouple services.

**Responsibilities:**
- Store pending jobs
- Support multiple worker types
- Allow controlled task consumption
- Keep the workflow asynchronous and modular

**Representative task types:**
- `recon_domain`
- `probe_host`
- `scan_http`
- `notify_finding`
- `refresh_domain`

**Persistence:**
Redis shall run with AOF (Append-Only File) persistence enabled (`appendonly yes`). On a Pi 5 with SSD-backed storage the performance impact of AOF is negligible. This ensures in-flight and pending queue items survive a container restart or host reboot. RDB snapshots are not sufficient alone because they can miss recently enqueued tasks.

**Task consumption pattern:**
Workers shall consume tasks using the `LMOVE source processing BRPOPLPUSH` pattern (Redis ≥ 6.2) or the equivalent `BRPOPLPUSH` on older builds. Tasks move from the main queue list to a per-worker processing list atomically. On worker crash or restart, tasks in the processing list are recoverable and must be re-enqueued by a watchdog or on startup.

**Dead-letter queue:**
Tasks that exhaust all retries shall be moved to a `dlq:<task_type>` list in Redis and also written to the `failed_jobs` table in SQLite. This makes failures visible and recoverable without re-enqueuing.

**Notes:**
Redis is used for speed and simplicity. Persistent results shall not rely only on Redis — SQLite and bind-mounted files are the authoritative record.

---

### 6.3 Recon Worker
**Purpose:** Discover assets for a target domain.

**Tools:**
- Subfinder (ARM64 binary required — use `ghcr.io/projectdiscovery/subfinder` with explicit `linux/arm64` platform tag)
- Amass (ARM64 binary required — use `ghcr.io/owasp-amass/amass` with explicit `linux/arm64` platform tag)

**Responsibilities:**
- Run subfinder and amass concurrently in background threads, streaming stdout line-by-line
- Enqueue `probe_host` for each new in-scope hostname as it is discovered — without waiting for either tool to finish
- Deduplicate discovered hostnames across tools within a single run
- Filter discovered hostnames against the authorized scope before enqueuing (see section 7.6)
- Gracefully handle amass binary absence

**Inputs:**
- `recon_domain(domain)`

**Outputs:**
- New subdomains stored in database
- `probe_host(hostname)` tasks for unseen or expired assets

**Operational policy:**
- Subfinder should be the default first pass
- Amass should default to passive mode
- Active Amass should be optional and disabled by default in v1

---

### 6.4 HTTP Worker
**Purpose:** Test discovered hosts for reachable web services.

**Tool:**
- httpx (ARM64 binary required — use `ghcr.io/projectdiscovery/httpx` with explicit `linux/arm64` platform tag)

**Responsibilities:**
- Probe target hosts over HTTP and HTTPS
- Record status, title, technologies, resolved URLs, and metadata
- Deduplicate endpoints
- Enqueue Nuclei scans for new or changed live endpoints

**Inputs:**
- `probe_host(hostname)`

**Outputs:**
- Endpoint records in storage
- `scan_http(url)` tasks

**Selection behavior:**
- Only alive HTTP(S) targets should move to the scan stage
- Recently probed unchanged targets may be skipped until TTL expires

---

### 6.5 Nuclei Worker
**Purpose:** Run template-based security checks on alive endpoints.

**Tool:**
- Nuclei (ARM64 binary required — use `ghcr.io/projectdiscovery/nuclei` with explicit `linux/arm64` platform tag)

**Responsibilities:**
- Scan URLs using curated templates, streaming JSONL output line-by-line via `Popen`
- Persist each finding and enqueue `notify_finding` immediately as nuclei outputs it — not after the full scan completes
- Deduplicate repeat findings
- Trigger alerts only for newly observed findings that meet the severity threshold

**Inputs:**
- `scan_http(url)`

**Outputs:**
- Findings in storage
- `notify_finding(finding_id)` for notable results

**Policy:**
- Prefer curated low-noise templates in v1
- Severity threshold for alerting should be configurable
- Avoid scanning every endpoint with every template by default

**Template management:**
Templates are mounted from a bind mount at `/opt/recon-platform/nuclei-templates`. A dedicated `nuclei-template-updater` init container or lightweight sidecar runs `nuclei -update-templates -update-directory /templates` on container start and on a configurable daily cron. The worker waits for the template directory to be populated before processing its first task. Template version is logged at worker startup for auditability.

---

### 6.6 Storage Layer
**Purpose:** Persist targets, assets, endpoints, scans, and findings.

**Recommended design:**
- SQLite for structured metadata
- Bind-mounted JSONL or JSON files for raw tool output and auditability

**Why SQLite:**
- Low overhead
- Good fit for a Pi
- Easy backups
- Easy local querying

**Required SQLite configuration:**
WAL (Write-Ahead Logging) mode shall be enabled at database initialization: `PRAGMA journal_mode=WAL`. This allows multiple workers to write concurrently without producing `SQLITE_BUSY` errors. WAL mode is persistent and does not need to be re-applied on each connection.

**Core entities:**
- Targets
- Jobs
- Failed jobs
- Subdomains
- HTTP endpoints
- Scan runs
- Findings
- Notifications

---

### 6.7 Notification Worker
**Purpose:** Send actionable results to the operator.

**Status:** Mandatory in v1. Without the notification worker, findings sit silently in SQLite with no operator signal.

**Outputs:**
- Telegram
- Discord webhook
- Local log file

**Notification triggers:**
- New subdomain discovered
- New live endpoint found
- New high-severity finding
- Reappearance of a previously closed issue

**Alert policy:**
Default to notifying only on new items above a configurable severity threshold to avoid fatigue.

---

### 6.8 Optional API / Viewer
**Purpose:** Give a minimal local way to inspect current state.

**Possible features:**
- List targets
- Show recent jobs
- Show new subdomains
- Show alive endpoints
- Show unresolved findings

**Implementation approach:**
A lightweight Flask or FastAPI service is sufficient. This is optional in v1.

---

## 7. Queue and Workflow Design

### 7.1 Base workflow

```text
Target submitted
  -> recon_domain(domain)
  -> subfinder/amass output
  -> probe_host(subdomain)
  -> httpx output
  -> scan_http(url)
  -> nuclei output
  -> notify_finding(finding)
```

### 7.2 Why the queue exists
Compared with cron-only execution, the queue provides:
- On-demand downstream execution
- Better deduplication
- Easier rate limiting
- Easier future scaling to multiple workers
- Lower API waste and lower re-scan noise

### 7.3 Deduplication rules
At minimum the system should deduplicate on:
- Domain + hostname for discovered assets
- URL + scheme + port for HTTP endpoints
- Template ID + affected endpoint for findings
- Task type + target + freshness window for queued tasks

### 7.4 Retry policy
Recommended default:
- Temporary network/tool error: retry up to 2 times
- Permanent input error: mark failed and do not retry
- Downstream tasks should not be created if upstream job failed
- Tasks that exhaust retries are moved to the dead-letter queue (`dlq:<task_type>` Redis list) and written to the `failed_jobs` table in SQLite with failure reason and timestamp

### 7.5 Scope enforcement
Before a discovered hostname is enqueued as a `probe_host` task, the recon worker shall validate it against the authorized scope.

Rules:
- The scope root is stored per target (e.g. `example.com`)
- A hostname is in scope if it equals the scope root or is a subdomain of it (i.e. ends with `.example.com`)
- Out-of-scope hostnames are discarded and optionally logged for audit, but never enqueued
- Wildcard scope entries (e.g. `*.example.com`) are normalized to the base domain for matching purposes

This check shall occur in the recon worker, not the HTTP worker, to prevent out-of-scope probing further down the pipeline.

### 7.6 TTL / freshness suggestions
- Domain recon refresh: every 12 to 24 hours
- HTTP reprobe for known alive endpoints: every 6 to 12 hours
- Nuclei rescan: every 12 to 24 hours, or only on changed endpoints

These values should be configurable.

---

## 8. Data Model (Logical)

### 8.1 targets
- id
- scope_root
- created_at
- enabled
- notes

### 8.2 jobs
- id
- type
- target_ref
- status
- created_at
- started_at
- finished_at
- retry_count
- worker_name
- raw_output_path

### 8.3 subdomains
- id
- target_id
- hostname
- source
- first_seen
- last_seen
- status

### 8.4 endpoints
- id
- subdomain_id
- url
- scheme
- host
- port
- title
- technologies
- status_code
- first_seen
- last_seen
- alive

### 8.5 findings
- id
- endpoint_id
- scanner
- template_id
- severity
- title
- matched_at
- first_seen
- last_seen
- raw_blob_path
- dedupe_key

### 8.6 failed_jobs
- id
- original_job_id
- type
- target_ref
- payload (JSON)
- failure_reason
- retry_count
- failed_at

### 8.7 notifications
- id
- finding_id
- channel
- sent_at
- delivery_status

---

## 9. Functional Requirements

### FR-1 Target management
The operator shall be able to add a target domain to the platform.

### FR-2 Recon scheduling
The platform shall enqueue a recon task when a new target is added.

### FR-3 Passive-first discovery
The platform shall prefer passive discovery before any more aggressive mode.

### FR-4 Asset persistence
The platform shall store discovered subdomains with timestamps and source attribution where available.

### FR-5 Endpoint discovery
The platform shall probe discovered hosts and store live HTTP(S) endpoints.

### FR-6 Scan triggering
The platform shall enqueue a vulnerability scan only for alive or changed endpoints.

### FR-7 Finding persistence
The platform shall persist findings with severity, source template, and timestamps.

### FR-8 Deduplication
The platform shall avoid duplicate jobs and duplicate notifications within a defined freshness window.

### FR-9 Notifications
The platform shall send notifications for new findings that match configured severity thresholds.

### FR-10 Operability
The platform shall be deployable as a Portainer stack using bind mounts and environment variables.

### FR-11 Scope enforcement
The platform shall discard any discovered hostname that is not a subdomain of the authorized target scope root before enqueuing downstream tasks.

### FR-12 Failure tracking
The platform shall record exhausted-retry tasks in a dead-letter queue and in persistent storage with failure reason and timestamp.

### FR-13 Template currency
The platform shall update Nuclei templates on startup and on a configurable interval without operator intervention.

---

## 10. Non-Functional Requirements

### NFR-1 Resource efficiency
The platform should be usable on a Raspberry Pi 5 with moderate RAM and SSD-backed storage.

### NFR-2 Recoverability
Containers should restart automatically after host reboot or service interruption.

### NFR-3 Transparency
Raw tool output should be preserved for later inspection.

### NFR-4 Extensibility
New worker types should be addable without redesigning the full system.

### NFR-5 Low operational complexity
The base deployment should avoid unnecessary external dependencies.

### NFR-6 Controlled network behavior
Concurrency and scan intensity should be configurable to reduce unnecessary traffic spikes and rate-limit issues.

---

## 11. Deployment View

### Required containers in v1
- `redis`
- `ingestor` or `scheduler`
- `worker-recon`
- `worker-httpx`
- `worker-nuclei`
- `worker-notify` (mandatory)

### Persistent volumes / bind mounts
Recommended bind mounts:
- `/opt/recon-platform/data/db` -> SQLite DB
- `/opt/recon-platform/data/output` -> raw JSONL/JSON results
- `/opt/recon-platform/config` -> app configs and secrets templates
- `/opt/recon-platform/logs` -> local service logs
- `/opt/recon-platform/nuclei-templates` -> Nuclei template directory (shared between updater and worker)

### Network model
- Single internal Docker network for service-to-service communication
- Optional reverse proxy only if a web viewer/API is exposed

---

## 12. Configuration Surface

Expected environment variables or config keys:
- `REDIS_URL`
- `SQLITE_PATH`
- `OUTPUT_DIR`
- `NUCLEI_TEMPLATES_DIR`
- `NUCLEI_TEMPLATES_UPDATE_INTERVAL_HOURS`
- `DEFAULT_RECON_INTERVAL_HOURS`
- `DEFAULT_HTTPX_INTERVAL_HOURS`
- `DEFAULT_NUCLEI_INTERVAL_HOURS`
- `MAX_RECON_CONCURRENCY`
- `MAX_HTTPX_CONCURRENCY`
- `MAX_NUCLEI_CONCURRENCY`
- `AMASS_TIMEOUT_MINUTES`
- `NUCLEI_SEVERITY_MIN`
- `NUCLEI_PROC_TIMEOUT`
- `TELEGRAM_BOT_TOKEN` (optional)
- `TELEGRAM_CHAT_ID` (optional)
- `DISCORD_WEBHOOK_URL` (optional)

**Passive recon provider API keys:**
Subfinder and Amass support external provider APIs (Shodan, Censys, SecurityTrails, VirusTotal, etc.) which significantly improve passive coverage. These keys shall be passed as stack environment variables and written into tool-specific provider config files at container startup by an entrypoint script. Supported keys:
- `SUBFINDER_SHODAN_API_KEY` (optional)
- `SUBFINDER_CENSYS_API_ID` / `SUBFINDER_CENSYS_API_SECRET` (optional)
- `SUBFINDER_SECURITYTRAILS_API_KEY` (optional)
- `SUBFINDER_VIRUSTOTAL_API_KEY` (optional)
- `AMASS_SHODAN_API_KEY` (optional)

These variables are optional. When absent the tools fall back to sources that require no authentication.

---

## 13. Safe Operating Model

This platform should support an operational model that minimizes waste and rate-limit exposure.

### Recommended defaults
- Subfinder enabled by default
- Amass passive mode enabled by default
- Aggressive Amass modes disabled by default
- Low worker concurrency
- Incremental scans only
- Notification threshold at medium or high severity

### Why this matters
A queue-based platform is useful partly because it reduces unnecessary repeated requests. Instead of rescanning all assets on a fixed interval, the platform can focus on new or stale items only.

---

## 14. Future Extensions

Planned but out of scope for the first stack:
- Headless screenshots of live apps
- Content discovery worker
- JavaScript analysis worker
- ASN and CIDR expansion modules
- WHOIS / certificate enrichment
- Asset tagging by program or owner
- Multi-tenant case/project separation
- Search UI over historical results

---

## 15. Recommended v1 Build Order

### Phase 1
- Redis (with AOF persistence)
- SQLite-backed controller (WAL mode)
- Recon worker (ARM64, with scope enforcement)
- HTTP worker (ARM64)
- Nuclei worker (ARM64, with template updater)
- Notification worker
- File-based logs and output

### Phase 2
- Minimal API / dashboard
- Periodic refresh logic

### Phase 3
- Advanced enrichment workers
- Program-specific tuning
- Smarter change detection

---

## 16. Deliverables for the Next Step

The next implementation document should translate this architecture into:
1. Portainer-compatible `docker-compose.yml`
2. Directory layout for bind mounts
3. Worker container definitions
4. Example `.env` file
5. Operational runbook
6. Minimal target submission workflow

---

## 17. Summary

The recommended platform is a small, event-driven reconnaissance system built around Redis queues and a few focused workers. On a Raspberry Pi 5, this provides a good balance between capability and operational simplicity.

The key architectural choice is the queue:
- It prevents blind full rescans
- It makes the platform incremental
- It enables controlled pacing
- It makes future growth easy

This gives you a realistic “auto recon daemon / bug bounty assistant” foundation without jumping straight into a heavy, brittle stack.
