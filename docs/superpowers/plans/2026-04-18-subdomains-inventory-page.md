# Subdomains Inventory Page Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a dedicated global subdomains inventory page to the ingestor dashboard, with one row per hostname and server-side filtering/sorting for target, status, search, last seen, and technology tags.

**Architecture:** Extend the existing `GET /subdomains` endpoint in `ingestor/app.py` so it returns hostname-level aggregates derived from `endpoints`, then add a new `/ui/subdomains.html` page that uses the shared static shell and reads those filters from URL query params.

**Tech Stack:** FastAPI, SQLite, vanilla JavaScript, Pico.css, pytest, TestClient

---

## File Map

| File | What changes |
|------|-------------|
| `ingestor/app.py` | Extend `GET /subdomains` with aggregate fields, filters, sorting, and pagination |
| `ingestor/tests/test_api_dashboard_v2.py` | Add API tests for hostname aggregation, filtering, and sorting |
| `ingestor/static/app.js` | Add `initSubdomains()` page logic, filter syncing, table rendering, and detail panel behavior |
| `ingestor/static/app.css` | Add styles for the subdomains filter bar, table, and detail panel only where existing shared styles are insufficient |
| `ingestor/static/subdomains.html` | New page using shared shell/assets |
| `ingestor/static/index.html` | Add `Subdomains` link in shared navigation |
| `ingestor/static/findings.html` | Add `Subdomains` link in shared navigation |
| `ingestor/static/targets.html` | Add `Subdomains` link in shared navigation |
| `ingestor/static/ops.html` | Add `Subdomains` link in shared navigation |
| `docs/api.md` | Document the extended `GET /subdomains` contract |

---

## Task 1: Add failing API tests for hostname aggregation and filters

**Files:**
- Modify: `ingestor/tests/test_api_dashboard_v2.py`

- [ ] Add a helper that can insert multiple endpoints under the same subdomain with different `alive`, `last_seen`, and `technologies` values as needed by the tests.
- [ ] Add failing tests for `GET /subdomains` returning one row per hostname with:
  - `status`
  - `endpoint_count`
  - `alive_endpoint_count`
  - `technology_tags`
  - `target_id`
  - `scope_root`
- [ ] Add failing tests for filtering by:
  - `target_id`
  - `status=online`
  - `status=offline`
  - `technology=wordpress`
  - `search=<substring>`
- [ ] Add failing tests for sorting by:
  - `hostname`
  - `last_seen`
  - `status`
- [ ] Add a test that subdomains with no endpoints still appear and are marked `offline`.
- [ ] Add a test that malformed endpoint `technologies` JSON is ignored instead of failing the response.
- [ ] Run: `pytest ingestor/tests/test_api_dashboard_v2.py -k subdomains -v`

---

## Task 2: Extend `GET /subdomains` in the backend

**Files:**
- Modify: `ingestor/app.py`

- [ ] Add query validation for:
  - `status`
  - `technology`
  - `search`
  - `sort_by`
  - `sort_dir`
  - `offset`
- [ ] Replace the current simple `/subdomains` query with a hostname-level aggregate query built from `subdomains`, `targets`, and `endpoints`.
- [ ] Return additive fields:
  - `target_id`
  - `status`
  - `endpoint_count`
  - `alive_endpoint_count`
  - `technology_tags`
- [ ] Implement `status` rollup as `online` when any endpoint for the hostname has `alive = 1`, otherwise `offline`.
- [ ] Implement server-side filtering for `target_id`, `status`, and `search`.
- [ ] Implement technology filtering against the aggregated technology set for the hostname using case-insensitive matching.
- [ ] Implement deterministic sorting for `hostname`, `last_seen`, `status`, and `scope_root`.
- [ ] Preserve backward compatibility for existing callers that only send `target_id` and `limit`.
- [ ] Run: `pytest ingestor/tests/test_api_dashboard_v2.py -k subdomains -v`

---

## Task 3: Add the Subdomains page shell and navigation

**Files:**
- Create: `ingestor/static/subdomains.html`
- Modify: `ingestor/static/index.html`
- Modify: `ingestor/static/findings.html`
- Modify: `ingestor/static/targets.html`
- Modify: `ingestor/static/ops.html`

- [ ] Create `ingestor/static/subdomains.html` using the same shared shell pattern as the existing pages.
- [ ] Add the `Subdomains` nav entry to all dashboard pages and mark it active on `subdomains.html`.
- [ ] Add a compact page header describing the page as the global hostname inventory.
- [ ] Add filter controls for:
  - target
  - status
  - technology
  - hostname search
  - sort field
  - sort direction
- [ ] Add the hostname inventory table with columns:
  - hostname
  - target
  - status
  - last seen
  - endpoint count
- [ ] Add the detail panel container for row selection, keeping the panel subdomain-centered.

---

## Task 4: Wire the new page into shared frontend logic

**Files:**
- Modify: `ingestor/static/app.js`
- Modify: `ingestor/static/app.css`

- [ ] Add an `initSubdomains()` page initializer keyed off `data-page="subdomains"`.
- [ ] Load target options from the existing metadata/target sources already used elsewhere in the dashboard.
- [ ] Parse filters from the page URL on load and hydrate the controls from those params.
- [ ] Build `/subdomains` requests from the selected filters and keep the URL in sync when filters change.
- [ ] Render one row per hostname and keep technology tags out of the table.
- [ ] Implement row selection and render the detail panel with:
  - hostname
  - scope root
  - status
  - first seen
  - last seen
  - source
  - endpoint counts
  - aggregated technology tags
- [ ] Reuse existing shared helpers and styles where possible instead of creating a page-specific JS/CSS architecture.
- [ ] Add only the minimum CSS needed for any new layout hooks or detail panel states not already covered by the shared UI system.

---

## Task 5: Document the API contract

**Files:**
- Modify: `docs/api.md`

- [ ] Update the `GET /subdomains` documentation to include:
  - new response fields
  - `status`, `technology`, `search`, `sort_by`, `sort_dir`, `offset`
  - hostname-level rollup semantics
- [ ] Keep the docs explicit that the resource is still one row per subdomain hostname, not one row per endpoint.

---

## Task 6: Verification

**Files:**
- Verify: `ingestor/tests/test_api_dashboard_v2.py`
- Verify: `ingestor/static/subdomains.html`
- Verify: `ingestor/static/app.js`
- Verify: `ingestor/static/app.css`
- Verify: `docs/api.md`

- [ ] Run: `pytest ingestor/tests/test_api_dashboard_v2.py -v`
- [ ] Manually inspect that all five dashboard pages include the same navigation with the new `Subdomains` entry.
- [ ] Manually inspect `subdomains.html` for the expected hooks and IDs referenced by `initSubdomains()`.
- [ ] Confirm the page requests `/subdomains` with the expected filters and sorting params.
- [ ] Sanity-check the detail panel behavior for:
  - a hostname with live endpoints
  - a hostname with no live endpoints
  - a hostname with aggregated technologies such as `wordpress`
- [ ] Verify that existing pages still load without broken navigation or shared-asset regressions.
