# Spec: Subdomains Inventory Page

**Date:** 2026-04-18  
**Status:** Drafted for review

## Goal

Add a dedicated global inventory page to the ingestor dashboard for discovered subdomains. The page should let operators inspect one row per subdomain hostname across all targets, with filtering and sorting by target, hostname, last seen date, online/offline status, and detected technology stack.

This is intended to fill the current product gap where subdomain discovery data exists in the platform but is not available in a focused operator view that supports inventory-style review.

## Scope

This design applies to:

- `ingestor/app.py`
- `ingestor/tests/test_api_dashboard_v2.py`
- `ingestor/static/app.js`
- `ingestor/static/app.css`
- `ingestor/static/subdomains.html`
- shared navigation markup in the existing static HTML pages
- `docs/api.md`

This feature adds a new dashboard page and extends the existing subdomain API contract. It does not add a new frontend framework, build tooling, or a separate endpoint family unless future scale forces that change.

## User Requirements Captured

- The page is a **global inventory page**, not a per-target drilldown page.
- The inventory uses **one row per subdomain hostname**, not one row per endpoint.
- Operators need sorting and filtering by:
  - target
  - last seen date
  - hostname
  - status (`online` / `offline`)
- Technology stack information should appear in a **detail panel**, not inline in the table.
- Technology must also be a **filterable value**, for example to find only WordPress hosts.
- Hostname status should be `online` if **any** endpoint under that subdomain is alive.

## Recommended Approach

Extend the existing `GET /subdomains` endpoint with additive aggregate fields and filtering capabilities, then add a dedicated `/ui/subdomains.html` page inside the shared dashboard shell.

This is preferred over introducing a separate inventory endpoint because:

- the underlying record model is already the `subdomains` table
- the existing endpoint already establishes the hostname-level resource
- additive fields preserve backward compatibility for existing callers
- the UI can be added cleanly without inventing a parallel reporting contract

## API Design

### Existing Endpoint Extension

Keep `GET /subdomains` as the source for the inventory page and extend it with optional filters, sorting, and aggregate row fields.

Existing callers using only `target_id` and `limit` must continue to work unchanged.

### Response Model

Each row represents a single `subdomains` record and includes:

- `id`
- `target_id`
- `scope_root`
- `hostname`
- `source`
- `first_seen`
- `last_seen`
- `status`
- `endpoint_count`
- `alive_endpoint_count`
- `technology_tags`

Definitions:

- `status` is `online` when at least one endpoint under the hostname has `alive = 1`
- `status` is `offline` otherwise
- `endpoint_count` is the total number of endpoints associated with the hostname
- `alive_endpoint_count` is the number of currently alive endpoints associated with the hostname
- `technology_tags` is the distinct union of all technologies found in `endpoints.technologies` for endpoints under that hostname

### Query Parameters

Add optional query parameters:

- `target_id`
- `status`
- `technology`
- `search`
- `sort_by`
- `sort_dir`
- `limit`
- `offset`

Supported semantics:

- `status`: `online` or `offline`
- `technology`: case-insensitive exact match against normalized aggregated technology tags
- `search`: case-insensitive substring match on hostname
- `sort_by`: `last_seen`, `hostname`, `status`, `scope_root`
- `sort_dir`: `asc` or `desc`

### Query Strategy

Build the query from `subdomains s`:

- join `targets t` on `s.target_id = t.id`
- left join `endpoints e` on `e.subdomain_id = s.id`

Aggregate per hostname row:

- `COUNT(e.id)` as `endpoint_count`
- `SUM(CASE WHEN e.alive = 1 THEN 1 ELSE 0 END)` as `alive_endpoint_count`
- derived `status`
- parsed and deduplicated `technology_tags`

Technology aggregation should tolerate malformed or null `endpoints.technologies` values by skipping invalid rows rather than failing the entire response.

## UI Design

### Navigation

Add a new page at `/ui/subdomains.html` and include it in the shared top navigation between `Targets` and `Ops`.

The new page should use the same shell, tone, spacing system, and shared assets as the existing dashboard pages.

### Page Layout

The page has three primary areas:

1. A compact page header
2. A filter/sort control bar
3. A hostname inventory table with a detail panel

### Page Header

The header should position the page as the global hostname inventory across all targets. It should emphasize inspection of discovered subdomains by freshness, reachability, and detected technology stack without turning into a broad target-management screen.

### Filter Bar

The filter bar should support:

- target filter
- status filter: `all`, `online`, `offline`
- technology filter
- hostname search
- sort field
- sort direction

All filters should round-trip through URL query parameters so the page is refresh-safe and shareable.

### Inventory Table

The table remains hostname-centered and intentionally compact.

Recommended columns:

- hostname
- target
- status
- last seen
- endpoint count

Technology tags should not appear inline in the table in v1. Keeping them out of the grid preserves scanability and avoids making the table visually noisy.

### Detail Panel

Selecting a row opens a detail panel that shows:

- hostname
- scope root
- status summary
- first seen
- last seen
- discovery source
- endpoint summary counts
- aggregated technology tags

The panel should remain subdomain-centered. It may reference endpoint-derived summary data, but it should not turn into a per-endpoint inspector in v1.

## Backend Behavior

### Status Rollup

Because one row represents one hostname, endpoint data is used only to derive row-level summary values.

Rollup rule:

- if any endpoint under the hostname is alive, mark the hostname `online`
- otherwise mark it `offline`

Subdomains with no endpoints should still appear and should be treated as `offline`.

### Technology Filtering

Technology filtering should:

- normalize tags case-insensitively
- match if any aggregated tag for the hostname equals the requested filter value
- exclude hosts with empty technology sets only when a technology filter is present

For v1, a single `technology` filter value is sufficient.

### Detail Data Loading

The detail panel should not require an extra API request in v1 if the list payload already contains the required fields.

If payload size becomes an issue later, the design can evolve to add `GET /subdomains/{id}` without changing the table model.

## Edge Cases

- A hostname with multiple endpoints is `online` if at least one endpoint is alive.
- A hostname with zero endpoints is `offline`.
- A hostname with null or malformed `technologies` JSON on some endpoints should still render; invalid entries are ignored.
- Sorting by `status` should use explicit deterministic ordering rather than relying on database lexical sort behavior.
- The page should not invent new freshness heuristics in v1; it should use the current persisted `alive` state and `last_seen` values already stored by the pipeline.

## Testing

### API Tests

Add tests for:

- hostname-level aggregation of `status`
- `endpoint_count` and `alive_endpoint_count`
- aggregated `technology_tags`
- filtering by `target_id`
- filtering by `status`
- filtering by `technology`
- sorting by `hostname`
- sorting by `last_seen`

### Static And Wiring Checks

Verify:

- `/ui/subdomains.html` is linked in shared navigation
- the new page uses the shared static assets
- the page requests `/subdomains` with the expected filter parameters

### Manual Sanity Checks

Confirm:

- the global inventory loads successfully
- selecting a row opens the detail panel
- filtering for a tag such as `wordpress` returns only matching hostnames
- offline-only filtering correctly includes hostnames with zero live endpoints

## Documentation

Update `docs/api.md` to document the extended `GET /subdomains` contract, including the new aggregate fields, filters, and sorting parameters.

## Out Of Scope

The following are not part of this design:

- one row per endpoint
- inline technology tags in the table
- endpoint drilldown UI
- new freshness heuristics beyond persisted database state
- frontend build tooling or framework migration
- a separate dedicated inventory API endpoint
