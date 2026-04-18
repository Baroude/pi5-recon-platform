# Spec: Dashboard UI Refresh

**Date:** 2026-04-18  
**Status:** Approved for implementation planning

## Goal

Refresh the ingestor dashboard UI across all four static pages so it looks cleaner, more uniform, and more modern without changing the underlying frontend architecture or backend contracts. The result should stay dark, information-dense, and operationally focused, but remove the current mix of glossy surfaces, uneven button emphasis, and inconsistent spacing that makes the interface feel improvised.

## Scope

This design applies to:

- `ingestor/static/index.html`
- `ingestor/static/findings.html`
- `ingestor/static/targets.html`
- `ingestor/static/ops.html`
- `ingestor/static/app.css`
- `ingestor/static/app.js` only where generated markup needs to align with the refreshed component styles

This is a visual and interaction cleanup pass. It is not a product redesign and does not add new backend features.

## Design Direction

The refreshed UI should use a restrained dark operations aesthetic:

- Keep dark mode across all pages.
- Reduce decorative gradients, glow, and visual noise.
- Preserve dense information layouts rather than expanding whitespace dramatically.
- Use a single primary accent color for navigation, focus states, and main actions.
- Keep semantic colors for health, severity, and destructive actions, but mute them so they read as metadata instead of decoration.
- Make the pages feel like one tool with one design language rather than four related screens.

The intended effect is "quietly professional": calmer surfaces, stronger alignment, and better action hierarchy, while still supporting operational scanning and triage workflows.

## User Preferences Captured

- Theme direction: cleaner and more restrained
- Coverage: all four pages
- Layout preference: information-dense

These preferences overrule broader "hero" styling or spacious enterprise-style layouts.

## Visual System

### Color

Replace the current glossy, high-contrast palette with a flatter neutral system:

- Background: near-black charcoal/slate instead of blue-heavy gradients
- Primary surface: dark neutral panel for cards, sections, dialogs, and tables
- Secondary surface: slightly lifted tone for nested blocks and inspectors
- Border: subtle cool-gray border used consistently across cards, tables, dialogs, and controls
- Accent: one restrained cool accent for active nav, focus rings, and primary actions
- Success/warning/error: retained for state indicators, but toned down and normalized

Decorative radial effects should be removed or reduced to the point that they do not define the interface.

### Typography

Keep the existing no-build stack and Pico baseline, but enforce clearer hierarchy:

- Page titles remain prominent, but shorter and less marketing-styled
- Supporting copy becomes shorter and lower contrast
- Metadata and timestamps use a quieter secondary text color
- Monospace remains limited to machine-oriented values such as IDs, payload fields, templates, and paths

The typography should read like an operations UI, not a landing page.

### Spacing And Shape

Standardize spacing and radii across the shell:

- Tighter vertical rhythm for dense operational views
- Shared padding scale for cards, tables, forms, and dialogs
- Smaller, more consistent corner radii
- Lighter shadow treatment so surfaces separate without glowing
- Consistent control heights for buttons, inputs, and selects

This is intended to improve density without making the pages feel cramped.

## Shared Shell

### Top Navigation

All four pages should share one consistent top bar treatment:

- Slimmer sticky header
- Quieter background with less blur/gloss emphasis
- Tighter nav pill spacing
- Clear active link state based on contrast, border, and subtle accent fill
- Status text aligned cleanly with the right side of the header

The nav should feel stable and utilitarian, not ornamental.

### Page Header Pattern

The current large hero styling should be reduced into a reusable page header pattern:

- Eyebrow remains optional but visually quieter
- One page title
- One short descriptive sentence
- One compact action row

Headers should establish page purpose quickly without consuming excessive vertical space.

### Surfaces

Use one surface system across metrics, panels, detail inspectors, dialogs, accordions, and payload cards:

- Primary panel surface for main content blocks
- Secondary surface for nested or supporting containers
- One border style
- One shadow style
- One radius system

This consistency is the main mechanism for making the frontend feel uniform.

## Component Rules

### Buttons

Normalize button hierarchy everywhere:

- One primary action per page header at most
- Standard actions use a shared secondary treatment
- Table actions use a compact subtle style unless they are the main operation
- Destructive actions use the danger treatment only

Mixed emphasis should be removed. Two actions with equal importance should not look unrelated.

### Pills And Badges

Severity, status, health, and queue badges should keep their semantics, but be visually calmer:

- Muted fills instead of bright color blocks
- Consistent size, padding, border treatment, and radius
- No badge should pull more attention than the row or card it belongs to

### Tables

Tables are the backbone of the UI and should become denser and more orderly:

- Reduced row height
- Better vertical alignment for action cells
- Consistent text contrast between primary and supporting columns
- Subtle hover states
- Action groups aligned and wrapped predictably

Tables should read as operational data grids rather than default browser tables with styled buttons dropped in.

### Forms

Create/edit/filter forms should use the same rhythm and control sizing:

- Labels aligned consistently
- Inputs and selects visually match buttons
- Multi-column forms collapse cleanly at smaller widths
- Switches and helper text align to the same spacing system as standard inputs

### Dialogs And Inspectors

Dialogs and right-side detail panels should be visually simplified:

- Same surface language as panels
- Less dramatic backdrops and gradients
- Stronger information grouping through spacing and borders
- Clearer separation between content and action areas

These elements should feel precise and controlled, especially for destructive actions.

## Page-Specific Design

### Dashboard

The dashboard remains the high-level operational view, but becomes visually quieter:

- Shorter page header
- Metric cards tightened and normalized
- Pipeline stage cards simplified so health and counts stand out more than decoration
- Worker activity table aligned with the rest of the shell
- Target overview table positioned as the anchor section of the page

The page should prioritize scanability over visual flourish.

### Findings

The findings page should optimize for fast review in a dense layout:

- Filters consolidated into a compact, consistent control bar
- Findings table becomes easier to scan by reducing action noise
- Inline triage buttons become smaller and visually secondary
- Detail panel becomes a structured inspector with clear metadata grouping

The default "open findings" workflow should remain obvious and fast.

### Targets

The targets page should feel like a clean configuration console:

- Create target form uses the same compact shell as filters and edit forms
- Inventory table aligns action density and status styling with the rest of the app
- Edit dialog becomes more neutral and less stylized
- Delete flow remains explicit, but calmer and more controlled visually

This page should feel operational, not administrative in a separate style.

### Ops

The ops page should match the same shell while preserving its recovery focus:

- Worker health and queue depth tables follow the same grid rules as the dashboard
- DLQ accordion treatment becomes cleaner and more compact
- Payload blocks use restrained borders and surfaces
- Failed jobs table aligns with the same badge, spacing, and action rules as other pages

The page should feel dense and technical, but not visually noisy.

## Interaction Constraints

- No new frontend framework
- No build tooling
- No backend API changes required for this refresh
- Existing polling behavior remains unchanged
- Existing page routes remain unchanged
- Existing functionality remains intact unless a markup cleanup requires a small JS update to preserve styling consistency

## Files And Expected Changes

### `ingestor/static/app.css`

Primary implementation area.

Expected changes:

- Replace the current token set with a restrained surface and spacing system
- Normalize nav, page headers, panels, metrics, badges, tables, forms, dialogs, and payload blocks
- Reduce decorative gradients and shadows
- Improve responsive behavior for dense action groups and forms

### `ingestor/static/index.html`

Expected changes:

- Reduce hero/header weight
- Align section framing with the shared shell
- Clean up button placement and action grouping

### `ingestor/static/findings.html`

Expected changes:

- Compact filter bar layout
- More consistent table/action markup hooks
- Cleaner detail panel framing

### `ingestor/static/targets.html`

Expected changes:

- Cleaner create form framing
- More uniform action placement in the inventory table
- Simplified dialog markup where needed for the refreshed styling

### `ingestor/static/ops.html`

Expected changes:

- Shared section framing and header cleanup
- Cleaner accordion and payload presentation
- More consistent dense table layout

### `ingestor/static/app.js`

Expected changes only if needed:

- Adjust generated classes or wrapper markup for buttons, cards, badges, or tables so the CSS system can style them consistently
- No behavioral redesign

## Verification

Manual verification is sufficient for this refresh:

- Confirm all four pages share the same shell and active navigation treatment
- Confirm buttons follow one hierarchy across pages
- Confirm badges are semantically clear but visually restrained
- Confirm tables are denser and more uniform
- Confirm dialogs and the finding detail panel feel visually integrated with the rest of the UI
- Confirm mobile/tablet breakpoints still collapse forms and action groups cleanly
- Confirm JS-generated markup still matches the final CSS hooks

## Out Of Scope

- Backend endpoint changes
- New pages or new workflows
- WebSocket/SSE changes
- A light theme
- A broad brand redesign
- Replacing Pico.css
- Functionality changes unrelated to the UI cleanup

## Recommendation

Implement this as a shared-shell-first refresh:

1. Update the token and component system in `app.css`
2. Normalize the four page templates to use that shared system consistently
3. Make only the minimum `app.js` markup changes required to match the new component rules
4. Verify all four pages visually as one coherent application

This ordering gives the best chance of fixing the "not uniform & clean" problem at the root instead of patching page-level symptoms.
