# Dashboard UX Overhaul Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the single-page dashboard with a multi-page Pico.css UI and add the backend/API support required for findings triage, DLQ actions, failed job visibility, and richer dashboard aggregation.

**Architecture:** Extend the existing FastAPI + SQLite + Redis backend first, keeping the current polling model and plain static HTML/JS delivery. Then split the current `ingestor/static/index.html` into shared static assets plus four focused pages that consume the new API contracts without introducing a build step.

**Tech Stack:** FastAPI, SQLite, Redis, plain HTML/CSS/JavaScript, Pico.css via CDN, pytest, TestClient

---

### Task 1: Schema and findings API contract

**Files:**
- Modify: `workers/common/db.py`
- Modify: `ingestor/app.py`
- Test: `ingestor/tests/test_api_dashboard_v2.py`

- [ ] Add failing tests for finding `status` in list/detail responses, comma-separated severity/status filters, and `PATCH /findings/{id}` validation.
- [ ] Run: `pytest ingestor/tests/test_api_dashboard_v2.py -k findings -v`
- [ ] Add the idempotent `findings.status` migration and extend list/detail/patch handlers with validated status support.
- [ ] Run: `pytest ingestor/tests/test_api_dashboard_v2.py -k findings -v`

### Task 2: Ops API contract

**Files:**
- Modify: `ingestor/app.py`
- Test: `ingestor/tests/test_api_dashboard_v2.py`

- [ ] Add failing tests for `GET /admin/dlq` raw and parsed payloads, `POST /admin/dlq/{queue}/requeue`, `POST /admin/dlq/{queue}/dismiss`, and `GET /admin/failed-jobs`.
- [ ] Run: `pytest ingestor/tests/test_api_dashboard_v2.py -k dlq -v`
- [ ] Implement raw-payload DLQ actions and failed-job listing with parsed payload support.
- [ ] Run: `pytest ingestor/tests/test_api_dashboard_v2.py -k 'dlq or failed_jobs' -v`

### Task 3: Dashboard aggregation changes

**Files:**
- Modify: `ingestor/app.py`
- Test: `ingestor/tests/test_api_dashboard_v2.py`

- [ ] Add failing tests for `overview.findings_open_total`, `overview.findings_open_window`, and per-target `finding_open_count`.
- [ ] Run: `pytest ingestor/tests/test_api_dashboard_v2.py -k progress -v`
- [ ] Extend `/admin/progress` queries to return the new open-finding aggregates without breaking existing fields.
- [ ] Run: `pytest ingestor/tests/test_api_dashboard_v2.py -k progress -v`

### Task 4: Shared static shell

**Files:**
- Create: `ingestor/static/app.css`
- Create: `ingestor/static/app.js`
- Modify: `ingestor/static/index.html`
- Create: `ingestor/static/findings.html`
- Create: `ingestor/static/targets.html`
- Create: `ingestor/static/ops.html`

- [ ] Extract shared nav, page shell, helpers, polling utilities, badges, and formatters into shared static assets.
- [ ] Convert `index.html` into the new Dashboard page using the new shell.
- [ ] Add Findings, Targets, and Ops pages wired to the shared helper layer.

### Task 5: Verification

**Files:**
- Verify: `ingestor/tests/test_api_dashboard_v2.py`
- Verify: `ingestor/static/index.html`
- Verify: `ingestor/static/findings.html`
- Verify: `ingestor/static/targets.html`
- Verify: `ingestor/static/ops.html`

- [ ] Run: `pytest ingestor/tests/test_api_dashboard_v2.py -v`
- [ ] Manually sanity-check page wiring by confirming the four HTML files reference the shared assets and expected endpoints.
- [ ] Inspect the rendered/static HTML for broken IDs or missing hooks.
