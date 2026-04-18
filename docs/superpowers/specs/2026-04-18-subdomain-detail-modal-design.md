# Spec: Subdomain Detail Modal

**Date:** 2026-04-18  
**Status:** Approved for implementation planning

## Goal

Replace the subdomains page's always-visible bottom detail section with a centered modal dialog so hostname inspection matches the findings page interaction model and no longer forces operators to scroll below the inventory table to see detail.

## Scope

This design applies to:

- `ingestor/static/subdomains.html`
- `ingestor/static/app.js`
- `ingestor/static/app.css`

This is an interaction and layout refinement for the subdomains inventory page only. It does not change backend APIs, subdomain filtering, or row data returned by `GET /subdomains`.

## Problem

The current subdomains page renders hostname details in a dedicated section below the inventory table. That makes the detail view less practical than the findings detail experience for three reasons:

- The operator has to scroll away from the selected row to inspect detail.
- The page keeps a large placeholder/detail region visible even when no hostname is being actively examined.
- The interaction diverges from the findings page, which already uses a centered modal detail view that is faster to understand and easier to dismiss.

The result is that the hostname list is usable, but the detail view feels secondary and physically disconnected from the row selection that triggered it.

## Design Direction

The subdomains page should follow the findings-page pattern closely:

- Row click opens a centered modal dialog.
- The list remains the primary surface behind the dialog.
- Detail is focused, temporary, and dismissible.
- The dialog keeps the same dark operational styling and structural hierarchy already established by the findings modal.

The target experience is "inspect in place, then return to scanning" rather than "scroll down into a second panel."

## User Preferences Captured

- Preferred interaction: centered modal dialog
- Reference pattern: findings detail experience
- Main complaint to solve: detail placed at the bottom of the hostname list is impractical

These preferences rule out keeping a persistent bottom detail panel or introducing a side inspector for this change.

## Interaction Model

### Opening Detail

- Clicking any hostname row in the subdomains table opens the hostname detail modal.
- The selected row remains the source of truth for what content the modal shows.
- Opening the modal should not navigate away, reload the page, or change filters.

### Closing Detail

The modal should close via:

- explicit close button
- clicking the backdrop
- pressing `Escape`

Closing the modal should return the operator to the table without resetting filters or table position.

### Refresh Behavior

The page already polls the backend for refreshed inventory data. While the modal is open:

- if the selected hostname still exists in the current filtered set, refresh the modal content in place
- if the selected hostname no longer exists in the filtered set, close the modal cleanly

This preserves the existing polling model without creating stale detail content.

## Modal Structure

The modal should reuse the findings dialog structure as much as possible.

### Header

The header should include:

- hostname as the main title
- status pill
- compact meta row containing:
  - target
  - source
  - first seen
  - last seen
- close button aligned in the header

The hostname remains the primary identifier. The target is supporting context rather than the headline.

### Body

The body should use the same overall visual language as findings detail:

- a structured two-column field grid for:
  - target
  - source
  - first seen
  - last seen
  - endpoint count
  - alive endpoint count
- a technology tags section below the grid

Technology tags remain outside the table so the inventory view stays scannable.

### Empty And Error States

- No modal is shown when no hostname is selected.
- If rendering detail fails for any reason, show an inline error state inside the dialog instead of breaking the page.
- If a hostname has no technology tags, render a quiet empty state message in that section.

## Page Layout Changes

### Remove Bottom Detail Section

Remove the persistent bottom hostname detail section from `subdomains.html`.

The page should retain:

- header
- filters
- hostname inventory table

The detail UI should move entirely into a modal `dialog` element.

### Table Behavior

The table remains unchanged in purpose:

- one row per hostname
- no technology tags in table rows
- row click is the primary way to inspect details

The only interaction change is where detail is rendered.

## Visual System

The modal should preserve consistency with the findings dialog instead of introducing a new visual component family.

### Reuse

Prefer reusing:

- existing `dialog` structure
- existing findings modal spacing
- existing header and meta-row patterns
- existing field-grid styling
- existing backdrop and close behavior

### Additions

Only add subdomain-specific CSS where existing findings styles do not fit cleanly, such as:

- modal title wrapping for long hostnames
- technology tag section spacing
- minor host-detail label/value presentation adjustments

The goal is visual alignment, not a second custom dialog system.

## Accessibility

- Use native `dialog` behavior for focus trapping.
- Keep the close control keyboard reachable.
- Preserve semantic table markup for the inventory list.
- Ensure the hostname title and status are immediately readable in the modal header.

No interaction in this change should depend on pointer-only behavior.

## Data And Backend Impact

No backend changes are required.

The modal should render directly from the selected row already returned by `GET /subdomains`, using the current response fields:

- `hostname`
- `scope_root`
- `source`
- `status`
- `first_seen`
- `last_seen`
- `endpoint_count`
- `alive_endpoint_count`
- `technology_tags`

This keeps the implementation constrained to the static dashboard layer.

## Verification

Implementation should verify:

- clicking a hostname row opens a centered dialog
- the dialog closes through button, backdrop, and `Escape`
- the inventory table remains usable after closing the dialog
- the dialog refreshes correctly while polling continues
- the dialog closes cleanly if the selected hostname disappears from the filtered result set
- mobile-width layouts no longer force the operator into a bottom detail region below the table

## Out Of Scope

The following are not part of this design:

- changing subdomain filters or sorting behavior
- adding new backend detail fields
- adding in-modal actions such as triage, tagging, or navigation controls
- redesigning the findings modal
- introducing a split-pane or persistent right-side inspector
