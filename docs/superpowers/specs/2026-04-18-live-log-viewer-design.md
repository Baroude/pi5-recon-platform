# Live Log Viewer — Design Spec

**Date:** 2026-04-18  
**Status:** Approved

## Overview

Add a Logs page to the ingestor UI that shows live, streaming output from each worker container. Workers currently buffer subprocess stdout until the tool exits; this spec changes that so output is logged line-by-line in real time. A new SSE-based API delivers those lines to the browser as they arrive.

---

## 1. Worker Changes

**Affected workers:** `worker-intel`, `worker-recon`, `worker-httpx`, `worker-nuclei`

Each worker has a helper function that runs an external tool via `subprocess.run(capture_output=True)`. Replace this with `subprocess.Popen` and a line-by-line read loop:

```python
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
lines = []
for line in proc.stdout:
    line = line.rstrip()
    if line:
        logger.info(line)
        lines.append(line)
proc.wait()
return lines
```

- Return value stays `list[str]` — callers are unchanged.
- stderr is merged into stdout so all tool output is captured.
- Timeout is enforced by wrapping with a thread or using `proc.communicate(timeout=...)` on the outer call.

**Log file paths** (already established):
| Worker | Log file |
|---|---|
| worker-intel | `/logs/worker-intel.log` |
| worker-recon | `/logs/worker-recon.log` |
| worker-httpx | `/logs/worker-httpx.log` |
| worker-nuclei | `/logs/worker-nuclei.log` |

---

## 2. Backend API

Two new endpoints added to `ingestor/app.py`.

### `GET /logs`
Returns the list of available workers derived from log files present in `/logs/*.log`.

```json
["worker-intel", "worker-recon", "worker-httpx", "worker-nuclei"]
```

### `GET /logs/{worker}?lines=500`
Reads the last `lines` lines from `/logs/{worker}.log` and returns them as a JSON array of strings. Used for the initial panel load and "Load full history" (lines=0 means all).

- Returns 404 if the log file does not exist.
- Max lines capped at 10 000 to avoid huge payloads.

### `GET /logs/{worker}/stream`
SSE endpoint. On connect:
1. Opens `/logs/{worker}.log`, seeks to end.
2. Enters a loop: reads any new lines, sends each as `data: <line>\n\n`.
3. Sleeps 200ms between reads if no new data.
4. Client disconnect closes the file and exits the loop.

Response headers: `Content-Type: text/event-stream`, `Cache-Control: no-cache`, `X-Accel-Buffering: no` (prevents nginx buffering).

---

## 3. Logs UI (`logs.html`)

New page, added to the nav bar on all pages.

### Layout

```
[ Worker: [dropdown ▼] ]   [ Load full history ]  [ Clear view ]

┌─────────────────────────────────────────────────────────────┐
│ 2026-04-18 19:18:47 worker-intel INFO worker-intel started  │
│ 2026-04-18 19:23:18 worker-intel INFO Running: amass intel  │
│ ...                                                         │
└─────────────────────────────────────────────────────────────┘
```

### Behaviour

- **On page load:** populate dropdown from `GET /logs`, default to first worker.
- **On worker select:** close existing SSE connection, fetch last 500 lines via `GET /logs/{worker}?lines=500`, display in panel, open new `EventSource` to `GET /logs/{worker}/stream`.
- **Auto-scroll:** panel auto-scrolls to bottom on new lines unless the user has scrolled up (detected via `scrollTop + clientHeight < scrollHeight - threshold`). A "↓ Jump to bottom" button appears when scroll is not at bottom.
- **Load full history:** calls `GET /logs/{worker}?lines=0`, replaces panel content, re-attaches SSE stream.
- **Clear view:** empties the panel DOM without closing the SSE stream — new lines continue to appear.
- **Line highlighting:**
  - `ERROR` lines: red tint
  - `WARNING` lines: amber tint
  - Normal lines: default monospace

### Error states

- If SSE disconnects unexpectedly, show a "Connection lost — reconnecting…" banner and retry with exponential backoff (1s, 2s, 4s, max 30s).
- If log file not found (404), show "No log file for this worker yet."

---

## 4. Data Flow

```
Worker subprocess → logger.info(line) → /logs/{worker}.log
                                              ↓
                              ingestor SSE endpoint reads new lines
                                              ↓
                              Browser EventSource receives data events
                                              ↓
                              Log panel appends + auto-scrolls
```

---

## 5. Out of Scope

- Log rotation or size management (handled by Docker/OS).
- Log search or filtering (plain browser Ctrl+F is sufficient for now).
- Multi-instance workers (one log file per worker type, not per container replica).
- Authentication on log endpoints (ingestor is already internal-only).
