# World Monitor — Security Assessment

A focused, presentation-ready security assessment prototype for the **World Monitor** web application.

The dashboard communicates one thing immediately:

> **This tool automatically tests a web application for important security controls and clearly shows what passed.**

It runs **8 verified security checks** against a local World Monitor instance and presents the results as clean, judge-friendly cards — green **PASS** states, concise evidence, and optional technical detail. It is designed as a product prototype (hackathon / SIH), not a developer debug tool.

---

## What it checks

| Category | Check | What it verifies | Typical evidence |
|---|---|---|---|
| **Authentication** | Session Cookie Security | Session cookies carry `HttpOnly`, `Secure`, `SameSite` | `HttpOnly ✓ SameSite=Lax ✓` (`Secure` only claimed over HTTPS) |
| **Input Security** | Path Traversal Protection | Malicious paths cannot escape the app's directory | `HTTP 400 · No file disclosure detected` |
| **Input Security** | Oversized Payload Protection | Huge requests are safely rejected, not crashed on | `HTTP 413 · Payload rejected` |
| **Input Security** | Reflected Input Protection | Script-like input is never reflected into responses | `HTTP 200 · Malicious payload not reflected` |
| **API Security** | CORS Protection | Untrusted origins cannot read the API cross-site | `HTTP 200 · Untrusted origin not reflected` |
| **Client Security** | Security Headers | CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` present | All four `✓` |
| **Client Security** | Production Source Maps | `.js.map` files are not publicly downloadable | `HTTP 404 · Source map not exposed` |
| **Client Security** | Health Endpoint Information Leakage | Health endpoint reveals no secrets or internals | `HTTP 200 · No sensitive-looking information detected · Detailed form key-gated` |

The UI has exactly five tabs: **Overview · Authentication · Input Security · API Security · Client Security**.

### "Cannot verify" is not a pass

A check that never reached the code under test reports **ERROR**, not **PASS**. This covers:

- **404 / 405 / 501** — the probed route does not exist, so nothing about the control was observed.
- **401 / 403** — the request was rejected before the behaviour under test ran (checked on the input-handling and health probes).

This matters in practice: if the World Monitor API layer is not mounted, every `/api/*` probe returns 404. Without this rule the suite would report a near-green dashboard for an app whose API is entirely absent. **Production Source Maps is the deliberate exception** — a 404 there is the desired result, demonstrating the file is genuinely not served, so it reports PASS.

Every evidence line is now derived from the actual response rather than a hardcoded expectation, so a card can never display an HTTP status the target did not send.

### Which health URL is the public one

`GET /api/health` is **not** public, and its `401` is not a failure. The detailed payload is gated behind an API key; a keyless caller gets `401` plus a hint pointing at the public form:

```json
{ "error": "…", "hint": "Detailed health requires an operator/enterprise API key. Public status: /api/health?compact=1" }
```

So the public-form check probes **`/api/health?compact=1`**, which is genuinely keyless, and records the detailed endpoint's `401` as an *evidence line* — a key-gated health payload is the desired posture, not a leak. (The CORS check uses the same URL, since it is the same path and therefore the same CORS decision.)

**Scope note:** this prototype demonstrates *verified* security controls. It intentionally excludes checks that produce unreliable results on a local deployment, and it never claims the application is "100% secure." Cookie values, API keys, and secrets are never displayed.

---

## Architecture

Two components, deliberately separated:

```
┌─────────────────────────┐         ┌──────────────────────────┐         ┌─────────────────────────┐
│   Browser (you)         │  HTTP   │  Scanner backend         │ raw HTTP│  World Monitor app      │
│                         │ ──────► │  security_scanner.py     │ ──────► │  http://localhost:3000  │
│  security-dashboard-    │         │  http://127.0.0.1:8000   │         │  (your running app)     │
│  v2.html                │ ◄────── │  - performs the checks   │ ◄────── │                         │
│  - tabs, cards, state   │  JSON   │  - returns evidence      │ headers │                         │
└─────────────────────────┘         └──────────────────────────┘         └─────────────────────────┘
```

**Why a Python backend?** Browsers cannot read security-relevant response headers such as `Set-Cookie` or test arbitrary cross-origin requests — CORS and browser sandboxing block it. The Python backend performs all raw HTTP requests itself and hands the dashboard clean, structured results. The dashboard is presentation only; no security logic lives in JavaScript.

### Components

| File | Role |
|---|---|
| `security_scanner.py` | Backend + check engine. Standard-library-only Python HTTP server on port **8000**. Runs the 8 checks, also serves the dashboard HTML. |
| `security-dashboard-v2.html` | The entire UI (single file): 5-tab layout, test cards, evidence chips, "View Details" tables, ambient radar background. |

### Backend API

| Endpoint | Method | Purpose |
|---|---|---|
| `/` | GET | Serves the dashboard HTML |
| `/health` | GET | Liveness check (`{"status": "ok"}`) |
| `/checks` | GET | JSON registry of the 8 checks |
| `/scan` | POST | Run **all** checks. Body: `{"target": "http://localhost:3000"}` |
| `/run` | POST | Run **one** check. Body: `{"id": "input-path-traversal", "target": "..."}` |
| `/report` | GET | Run **all** checks and return a complete report as a download. Query: `?target=...`, `?format=md\|json` (default `md`) |

Each result includes: `status` (`pass` / `warn` / `fail` / `error`), a human `detail`, `evidence` lines, `http_status`, sanitized `headers` (no secrets), the `request` performed, and `elapsed_ms`.

---

## Getting started

### Prerequisites

- **Python 3.8+** (standard library only — nothing to `pip install`)
- **World Monitor app running on `http://localhost:3000`**

### Run it

**1. Start World Monitor** (however you normally do — Docker, `npm start`, etc.) and confirm it is up:

```bash
curl -o /dev/null -w "HTTP %{http_code}\n" http://localhost:3000/
# → HTTP 200
```

**2. Start the scanner backend** (from this folder):

```bash
python security_scanner.py
```

```
World Monitor — Security Assessment API
Listening on http://127.0.0.1:8000
Target default: http://localhost:3000
Checks: 8 (verified set)
Press Ctrl+C to stop.
```

**3. Open the dashboard:**

> ### http://127.0.0.1:8000/

The backend serves the UI directly — no second server or `python -m http.server` needed. (You *may* still serve the HTML from any static server; the backend sends permissive CORS headers for that case.)

**4. Click ▶ Run All Checks.** Each card completes in turn (~160 ms total against a local app) and turns green. Open **View Details** on any card for the underlying HTTP evidence.

### Demo tip

Open **`http://127.0.0.1:8000/?autorun=1`** to auto-start the full suite the moment the page loads — useful so results are already on screen before a presentation begins.

---

## Project layout

```
.
├── security_scanner.py          # Backend: HTTP API + 8 check implementations
├── security-dashboard-v2.html   # Frontend: 5-tab dashboard (single file)
└── README.md
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| Dashboard says scanner unreachable / fetch errors | Start the backend first: `python security_scanner.py` |
| `Address already in use` on port 8000 | A stale scanner is running. Find and stop it: `netstat -ano \| findstr :8000` → `taskkill /PID <pid> /F` (Windows), then restart |
| All checks show **ERROR** | World Monitor isn't reachable on port 3000 — start the app and re-run |
| App runs on a different port | Change `state.target` in `security-dashboard-v2.html` (and `DEFAULT_TARGET` in `security_scanner.py` if you want the default to match) |
| Dashboard served from another origin (e.g. port 5500) | Works out of the box — the backend sends permissive CORS headers |

## Notes & limitations

- Checks are **non-destructive** probes (malformed paths, one oversized request, one script-like query parameter, one foreign `Origin` header) — safe to run against your local app.
- Results reflect **your local deployment** at scan time; they are not a certification of production security.
- The source-map check probes a common bundle path (`/assets/index.js.map`); adjust the path in `run_sourcemaps` if your app bundles differently.
