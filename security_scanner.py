#!/usr/bin/env python3
"""
World Monitor — Security Assessment backend.

Run:
    python security_scanner.py

Then open:
    http://127.0.0.1:5500/security-dashboard-v2.html
        (or http://127.0.0.1:8000/ — the backend serves the dashboard too)

The dashboard talks to this backend on port 8000. The backend performs the
raw HTTP requests against the World Monitor target (default
http://localhost:3000), avoiding browser CORS/header limitations.

Prototype scope: 8 verified checks across four categories.
"""

import json
import re
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urljoin, urlparse
from urllib.request import Request, urlopen

HOST = "127.0.0.1"
PORT = 8000
DEFAULT_TARGET = "http://localhost:3000"
TIMEOUT = 8

# Dashboard file served by this backend (same directory as this script).
DASHBOARD_FILE = Path(__file__).resolve().parent / "security-dashboard-v2.html"


def normalize_base(base):
    base = base.strip().rstrip("/")
    parsed = urlparse(base)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("Target must be a full http:// or https:// URL")
    return base


def request_raw(url, method="GET", headers=None, body=None, timeout=TIMEOUT):
    req = Request(
        url,
        data=body,
        headers=headers or {},
        method=method,
    )
    try:
        with urlopen(req, timeout=timeout) as r:
            data = r.read()
            return {
                "status": r.status,
                "headers": {k.lower(): v for k, v in r.headers.items()},
                "body": data,
                "error": None,
            }
    except HTTPError as e:
        try:
            data = e.read()
        except Exception:
            data = b""
        return {
            "status": e.code,
            "headers": {k.lower(): v for k, v in e.headers.items()},
            "body": data,
            "error": None,
        }
    except (URLError, TimeoutError, OSError) as e:
        return {
            "status": 0,
            "headers": {},
            "body": b"",
            "error": str(e),
        }


def text_body(result):
    return result["body"].decode("utf-8", errors="replace")


def pass_result(detail, evidence=None, http_status=None, headers=None, request=None):
    return {
        "status": "pass",
        "detail": detail,
        "evidence": evidence or [],
        "http_status": http_status,
        "headers": headers or [],
        "request": request,
    }


# Statuses that mean the probe never reached the code under test.
# 404/405/501: the route does not exist. 401/403: the request was rejected
# before the behaviour being checked ever ran. Neither is evidence that a
# security control works, so these must never be reported as a pass.
ROUTE_NOT_FOUND = (404, 405, 501)
AUTH_BLOCKED = (401, 403)


def fail_result(detail, evidence=None, http_status=None, headers=None, request=None):
    return {
        "status": "fail",
        "detail": detail,
        "evidence": evidence or [],
        "http_status": http_status,
        "headers": headers or [],
        "request": request,
    }


def warn_result(detail, evidence=None, http_status=None, headers=None, request=None):
    return {
        "status": "warn",
        "detail": detail,
        "evidence": evidence or [],
        "http_status": http_status,
        "headers": headers or [],
        "request": request,
    }


def error_result(detail, http_status=None, request=None):
    return {
        "status": "error",
        "detail": detail,
        "evidence": [],
        "http_status": http_status,
        "headers": [],
        "request": request,
    }


def cannot_verify(detail, http_status, request):
    """Report a check as unverifiable instead of passing it.

    Used when the probe hit a route that is missing or that rejected the
    request outright. Saying "we could not test this" is honest; reporting
    PASS would claim a control that was never exercised.
    """
    return error_result(
        f"Cannot verify — {detail} (HTTP {http_status}).",
        http_status=http_status,
        request=request,
    )


# --------------------------------------------------------------------------
# Category: Authentication
# --------------------------------------------------------------------------

def run_session_cookie_flags(base):
    """POST /api/wm-session and inspect Set-Cookie security flags."""
    request = {
        "method": "POST",
        "endpoint": "/api/wm-session",
        "summary": "Issue a session, then inspect the Set-Cookie attributes",
    }
    r = request_raw(urljoin(base + "/", "api/wm-session"), method="POST")
    if r["status"] == 0:
        return error_result(f"Request failed: {r['error']}")
    if r["status"] in ROUTE_NOT_FOUND:
        return cannot_verify(
            "POST /api/wm-session was not found, so no cookie could be inspected",
            r["status"],
            request,
        )

    set_cookie = r["headers"].get("set-cookie", "")
    if not set_cookie:
        return warn_result(
            f"HTTP {r['status']}; the endpoint responded but sent no Set-Cookie "
            "header. Verify whether this endpoint intentionally issues a cookie.",
            http_status=r["status"],
            request=request,
        )

    cookie_lower = set_cookie.lower()
    missing = []
    if "httponly" not in cookie_lower:
        missing.append("HttpOnly")
    if "samesite=" not in cookie_lower:
        missing.append("SameSite")
    if base.startswith("https://") and "secure" not in cookie_lower:
        missing.append("Secure")

    if missing:
        return fail_result(
            f"Set-Cookie observed but missing: {', '.join(missing)}.",
            http_status=r["status"],
            headers=[("Set-Cookie", "cookie value not shown")],
            request=request,
        )

    samesite = re.search(r"samesite=(\w+)", set_cookie, re.I)
    same_label = f"SameSite={samesite.group(1) if samesite else 'Lax'}"
    # Secure is only meaningful over HTTPS, so only claim it when it was checked.
    evidence = ["HttpOnly ✓", f"{same_label} ✓"]
    header_flags = ["HttpOnly", same_label]
    if base.startswith("https://"):
        evidence.insert(1, "Secure ✓")
        header_flags.insert(1, "Secure")
        detail = "Session cookie carries the HttpOnly, Secure and SameSite protections."
    else:
        evidence.insert(1, "Secure — not checked (target is plain HTTP)")
        detail = (
            "Session cookie carries HttpOnly and SameSite protections; Secure was "
            "not checked because the target is served over plain HTTP."
        )
    return pass_result(
        detail,
        evidence=evidence,
        http_status=r["status"],
        headers=[("Set-Cookie", "; ".join(header_flags) + " (cookie value not shown)")],
        request=request,
    )


# --------------------------------------------------------------------------
# Category: Input Security
# --------------------------------------------------------------------------

def run_path_traversal(base):
    """Malicious path must be rejected — no file disclosure."""
    path = "/api/..%2f..%2fetc%2fpasswd.md"
    request = {
        "method": "GET",
        "endpoint": path,
        "summary": "Traversal-style path requesting a file outside the app root",
    }
    r = request_raw(base + path)
    if r["status"] == 0:
        return error_result(f"Request failed: {r['error']}")
    txt = text_body(r)
    if re.search(r"root:.*:0:0:", txt):
        return fail_result(
            "Possible traversal — response looks like /etc/passwd contents.",
            http_status=r["status"],
            request=request,
        )
    if r["status"] in ROUTE_NOT_FOUND:
        return cannot_verify(
            "the probe returned "
            f"{r['status']}, and a missing route is indistinguishable from a "
            "path that was deliberately rejected",
            r["status"],
            request,
        )
    if r["status"] >= 500:
        return warn_result(
            f"HTTP {r['status']} on a malformed path — inspect manually.",
            http_status=r["status"],
            request=request,
        )
    return pass_result(
        "Malicious path did not disclose any file outside the application root.",
        evidence=[f"HTTP {r['status']}", "No file disclosure detected"],
        http_status=r["status"],
        headers=[],
        request=request,
    )


def run_oversized(base):
    """~2MB JSON payload must be safely rejected, not cause a server error."""
    request = {
        "method": "POST",
        "endpoint": "/api/ask",
        "summary": "~2 MB JSON body sent to the question endpoint",
    }
    big = ("x" * 2_000_000).encode()
    r = request_raw(
        urljoin(base + "/", "api/ask"),
        method="POST",
        headers={"Content-Type": "application/json"},
        body=json.dumps({"q": big.decode()}).encode(),
        timeout=15,
    )
    if r["status"] == 0:
        return error_result(f"Request failed: {r['error']}")
    if r["status"] in ROUTE_NOT_FOUND:
        return cannot_verify(
            "POST /api/ask was not found, so payload handling was never exercised",
            r["status"],
            request,
        )
    if r["status"] in AUTH_BLOCKED:
        return cannot_verify(
            f"the request was rejected with {r['status']} before it reached payload "
            "handling, so no size limit was tested",
            r["status"],
            request,
        )
    txt = text_body(r)
    if re.search(r"at\s+\S+\s+\(.*:\d+:\d+\)", txt):
        return fail_result(
            "Response body appears to contain a stack trace — verbose error leakage.",
            http_status=r["status"],
            request=request,
        )
    if r["status"] >= 500:
        return warn_result(
            f"HTTP {r['status']} on oversized input — inspect manually.",
            http_status=r["status"],
            request=request,
        )
    if r["status"] >= 400:
        return pass_result(
            "Oversized request was rejected without a server error.",
            evidence=[f"HTTP {r['status']}", "Payload rejected"],
            http_status=r["status"],
            headers=[],
            request=request,
        )
    return warn_result(
        f"HTTP {r['status']} — the ~2 MB payload was accepted rather than rejected. "
        "Confirm the endpoint enforces a request size limit.",
        http_status=r["status"],
        request=request,
    )


def run_xss_echo(base):
    """Script-like input must not be reflected raw in the response."""
    payload = "<script>window.__xsstest=1</script>"
    request = {
        "method": "GET",
        "endpoint": "/api/ask?q=<script>…</script>",
        "summary": "Script-tag-like value sent through the query parameter",
    }
    url = urljoin(base + "/", "api/ask") + "?q=" + quote(payload)
    r = request_raw(url)
    if r["status"] == 0:
        return error_result(f"Request failed: {r['error']}")
    if r["status"] in ROUTE_NOT_FOUND:
        return cannot_verify(
            "GET /api/ask was not found, so the parameter was never echoed back",
            r["status"],
            request,
        )
    if r["status"] in AUTH_BLOCKED:
        return cannot_verify(
            f"the request was rejected with {r['status']} before the parameter was "
            "processed, so reflection could not be observed",
            r["status"],
            request,
        )
    txt = text_body(r)
    if payload in txt:
        return fail_result(
            "Payload reflected unescaped in response body.",
            http_status=r["status"],
            request=request,
        )
    return pass_result(
        "Malicious payload was not reflected in the response.",
        evidence=[f"HTTP {r['status']}", "Malicious payload not reflected"],
        http_status=r["status"],
        headers=[],
        request=request,
    )


# --------------------------------------------------------------------------
# Category: API Security
# --------------------------------------------------------------------------

def run_cors(base):
    """Untrusted origin must not be allowed to read the API."""
    request = {
        "method": "GET",
        "endpoint": "/api/health?compact=1",
        "summary": "Request sent with Origin: https://evil.example",
    }
    r = request_raw(
        urljoin(base + "/", "api/health?compact=1"),
        headers={"Origin": "https://evil.example"},
    )
    if r["status"] == 0:
        return error_result(f"Request failed: {r['error']}")
    if r["status"] in ROUTE_NOT_FOUND:
        return cannot_verify(
            "GET /api/health?compact=1 was not found, so no CORS policy could be observed",
            r["status"],
            request,
        )
    acao = r["headers"].get("access-control-allow-origin")
    if acao == "https://evil.example":
        return fail_result(
            f"ACAO reflected untrusted origin: {acao}",
            http_status=r["status"],
            request=request,
        )
    return pass_result(
        "Untrusted origin cannot read API responses cross-site.",
        evidence=[f"HTTP {r['status']}", "Untrusted origin not reflected"],
        http_status=r["status"],
        headers=[
            (
                "Access-Control-Allow-Origin",
                acao if acao else "(not set — browser blocks cross-site reads)",
            ),
        ],
        request=request,
    )


# --------------------------------------------------------------------------
# Category: Client Security
# --------------------------------------------------------------------------

def run_security_headers(base):
    """CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy."""
    request = {
        "method": "GET",
        "endpoint": "/",
        "summary": "Inspect response headers on the application root",
    }
    r = request_raw(base + "/")
    if r["status"] == 0:
        return error_result(f"Request failed: {r['error']}")
    if r["status"] >= 400:
        return cannot_verify(
            f"the application root returned {r['status']}, so the served document "
            "could not be inspected",
            r["status"],
            request,
        )
    h = r["headers"]
    labels = [
        ("Content-Security-Policy", "content-security-policy"),
        ("X-Content-Type-Options", "x-content-type-options"),
        ("X-Frame-Options", "x-frame-options"),
        ("Referrer-Policy", "referrer-policy"),
    ]
    present, missing = [], []
    for label, key in labels:
        (present if h.get(key) else missing).append(label)
    if missing:
        return warn_result(
            f"Missing headers: {', '.join(missing)}",
            http_status=r["status"],
            request=request,
        )
    return pass_result(
        "All four browser security headers are present on the application.",
        evidence=[f"{label} ✓" for label, _ in labels],
        http_status=r["status"],
        headers=[(label, h.get(key, "")) for label, key in labels],
        request=request,
    )


def run_sourcemaps(base):
    """Production .js.map files must not be publicly downloadable.

    This is the one check where a 404 is the desired outcome, so — unlike the
    others — 404 is reported as PASS rather than "cannot verify". A 404 here
    directly demonstrates the file is not served; there is no missing-route
    ambiguity, because the asset either exists on disk or it does not.
    """
    request = {
        "method": "GET",
        "endpoint": "/assets/index.js.map",
        "summary": "Direct request for a production source-map file",
    }
    r = request_raw(urljoin(base + "/", "assets/index.js.map"))
    if r["status"] == 0:
        return error_result(f"Request failed: {r['error']}")
    if r["status"] == 404:
        return pass_result(
            "Source-map files are not exposed to the public.",
            evidence=["HTTP 404", "Source map not exposed"],
            http_status=r["status"],
            headers=[],
            request=request,
        )
    if r["status"] in ROUTE_NOT_FOUND:
        return cannot_verify(
            f"the asset path returned {r['status']} rather than 404, which says "
            "nothing about whether maps are served",
            r["status"],
            request,
        )
    return warn_result(
        f"HTTP {r['status']} — a map-like path responded; verify manually whether "
        "it is a real source map or a catch-all/index fallback.",
        http_status=r["status"],
        request=request,
    )


def run_health_verbosity(base):
    """Public health endpoint must not leak secrets or internal details.

    /api/health is NOT the public form. The detailed payload is gated behind
    validateApiKey(forceKey) and answers a keyless caller with 401 + a hint
    pointing at /api/health?compact=1 — so probing the bare path reports a
    deliberate rejection as though it were a finding. This check targets the
    documented public form, and separately records that the detailed form is
    key-gated (good posture, not a leak).
    """
    request = {
        "method": "GET",
        "endpoint": "/api/health?compact=1",
        "summary": "Scan the public health response for secret-like strings",
    }
    r = request_raw(urljoin(base + "/", "api/health?compact=1"))
    if r["status"] == 0:
        return error_result(f"Request failed: {r['error']}")
    if r["status"] in ROUTE_NOT_FOUND:
        return cannot_verify(
            "GET /api/health?compact=1 was not found, so no response body could be inspected",
            r["status"],
            request,
        )
    if r["status"] in AUTH_BLOCKED:
        return cannot_verify(
            f"the public health form returned {r['status']}, so its body could not be "
            "read and no leak could be ruled out",
            r["status"],
            request,
        )
    txt = text_body(r)

    # The detailed form is expected to require a key. Record that rather than
    # misreading its 401 as "the endpoint could not be reached".
    detail = request_raw(urljoin(base + "/", "api/health"))
    gated = detail["status"] in AUTH_BLOCKED

    suspicious = re.search(r"(secret|password|api[_-]?key|token)\s*[:=]", txt, re.I)
    if suspicious:
        return fail_result(
            "Health response contains strings resembling secrets/keys.",
            evidence=[
                f"HTTP {r['status']} on the public form",
                "Response contains secret-like strings",
            ],
            http_status=r["status"],
            request=request,
        )

    evidence = [f"HTTP {r['status']}", "No sensitive-looking information detected"]
    if r["status"] >= 500:
        evidence.append("Endpoint reports a degraded state")
    if gated:
        evidence.append(
            f"Detailed /api/health answers {detail['status']} without a key — "
            "full payload is key-gated"
        )
    return pass_result(
        "Public health endpoint reports status only — no internal details.",
        evidence=evidence,
        http_status=r["status"],
        headers=[],
        request=request,
    )


# --------------------------------------------------------------------------
# Test registry — 8 verified checks, organized by dashboard category
# --------------------------------------------------------------------------

CHECKS = [
    {
        "cat": "Authentication",
        "items": [
            ("sess-cookie-flags", "Session Cookie Security", run_session_cookie_flags),
        ],
    },
    {
        "cat": "Input Security",
        "items": [
            ("input-path-traversal", "Path Traversal Protection", run_path_traversal),
            ("input-oversized", "Oversized Payload Protection", run_oversized),
            ("input-xss-echo", "Reflected Input Protection", run_xss_echo),
        ],
    },
    {
        "cat": "API Security",
        "items": [
            ("api-cors-foreign-origin", "CORS Protection", run_cors),
        ],
    },
    {
        "cat": "Client Security",
        "items": [
            ("client-security-headers", "Security Headers", run_security_headers),
            ("client-sourcemaps", "Production Source Maps", run_sourcemaps),
            ("data-health-verbosity", "Health Endpoint Information Leakage", run_health_verbosity),
        ],
    },
]

CHECK_INDEX = {
    check_id: (group["cat"], name, func)
    for group in CHECKS
    for check_id, name, func in group["items"]
}


def run_check(check_id, target):
    """Run a single check and return {id, cat, name, result}."""
    cat, name, func = CHECK_INDEX[check_id]
    target = normalize_base(target)
    started = time.time()
    try:
        result = func(target)
    except Exception as exc:
        result = error_result(f"Scanner exception: {type(exc).__name__}: {exc}")
    result["elapsed_ms"] = round((time.time() - started) * 1000)
    return {"id": check_id, "cat": cat, "name": name, **result}


def run_all(target):
    """Run every check sequentially; returns the full scan payload."""
    target = normalize_base(target)
    results = {}
    for group in CHECKS:
        for check_id, _, _ in group["items"]:
            results[check_id] = run_check(check_id, target)
    return {
        "target": target,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "results": results,
    }


STATUS_LABEL = {
    "pass": "PASS",
    "warn": "WARN",
    "fail": "FAIL",
    "error": "ERROR",
    "not_run": "NOT RUN",
}


def summarize(scan):
    """Count results by status across the full check registry."""
    counts = {"pass": 0, "warn": 0, "fail": 0, "error": 0, "not_run": 0}
    for group in CHECKS:
        for check_id, _, _ in group["items"]:
            r = scan["results"].get(check_id)
            status = r.get("status") if r else "not_run"
            counts[status if status in counts else "error"] += 1
    return counts


def report_markdown(scan):
    """Full report covering every check, with evidence and HTTP detail."""
    counts = summarize(scan)
    total = sum(counts.values())
    lines = [
        "# World Monitor — Security Assessment Report",
        "",
        f"- **Generated:** {scan['generated']}",
        f"- **Target:** {scan['target']}",
        f"- **Checks executed:** {total - counts['not_run']} of {total}",
        "",
        "## Summary",
        "",
        "| Result | Count |",
        "|--------|-------|",
        f"| PASS | {counts['pass']} |",
        f"| WARN | {counts['warn']} |",
        f"| FAIL | {counts['fail']} |",
        f"| ERROR | {counts['error']} |",
        "",
    ]

    for group in CHECKS:
        lines.append(f"## {group['cat']}")
        lines.append("")
        for check_id, name, _ in group["items"]:
            r = scan["results"].get(check_id, {})
            status = r.get("status", "not_run")
            lines.append(f"### {name}")
            lines.append("")
            lines.append(f"- **Status:** {STATUS_LABEL.get(status, status.upper())}")
            lines.append(f"- **Check ID:** `{check_id}`")
            lines.append(f"- **Detail:** {r.get('detail', '')}")
            if r.get("http_status") is not None:
                lines.append(f"- **HTTP status:** {r['http_status']}")
            if r.get("elapsed_ms") is not None:
                lines.append(f"- **Elapsed:** {r['elapsed_ms']} ms")

            req = r.get("request")
            if req:
                lines.append(
                    f"- **Request:** `{req.get('method', 'GET')} {req.get('endpoint', '')}`"
                )
                if req.get("summary"):
                    lines.append(f"- **Probe:** {req['summary']}")

            if r.get("evidence"):
                lines.append("- **Evidence:**")
                for item in r["evidence"]:
                    lines.append(f"  - {item}")

            if r.get("headers"):
                lines.append("- **Response headers observed:**")
                for key, value in r["headers"]:
                    lines.append(f"  - `{key}: {value}`")

            lines.append("")

    lines += [
        "---",
        "",
        "Generated by `security_scanner.py`. Results reflect the target at scan "
        "time and are not a certification of production security.",
        "",
    ]
    return "\n".join(lines)


class Handler(BaseHTTPRequestHandler):
    def _send(self, status, payload, content_type="application/json", extra_headers=None):
        data = payload if isinstance(payload, bytes) else payload.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self._send(204, b"")

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._send(200, json.dumps({"status": "ok"}))
        elif parsed.path in ("/", "/index.html", "/security-dashboard-v2.html"):
            try:
                html = DASHBOARD_FILE.read_bytes()
                self._send(200, html, "text/html; charset=utf-8")
            except OSError:
                self._send(404, json.dumps({"error": "Dashboard file not found"}))
        elif parsed.path == "/report":
            params = parse_qs(parsed.query)
            target = params.get("target", [DEFAULT_TARGET])[0]
            fmt = params.get("format", ["md"])[0].lower()
            try:
                scan = run_all(target)
            except Exception as exc:
                self._send(400, json.dumps({"error": str(exc)}))
                return
            stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
            name = f"worldmonitor-security-report-{stamp}"
            if fmt == "json":
                self._send(
                    200,
                    json.dumps(scan, indent=2),
                    "application/json",
                    {"Content-Disposition": f'attachment; filename="{name}.json"'},
                )
            else:
                self._send(
                    200,
                    report_markdown(scan),
                    "text/markdown; charset=utf-8",
                    {"Content-Disposition": f'attachment; filename="{name}.md"'},
                )
        elif parsed.path == "/checks":
            listing = [
                {"id": cid, "cat": g["cat"], "name": name}
                for g in CHECKS
                for cid, name, _ in g["items"]
            ]
            self._send(200, json.dumps(listing))
        else:
            self._send(404, json.dumps({"error": "Not found"}))

    def do_POST(self):
        parsed = urlparse(self.path)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            payload = json.loads(raw or b"{}")
            target = payload.get("target", DEFAULT_TARGET)
        except Exception as exc:
            self._send(400, json.dumps({"error": f"Bad request: {exc}"}))
            return

        if parsed.path == "/scan":
            try:
                self._send(200, json.dumps(run_all(target)))
            except Exception as exc:
                self._send(400, json.dumps({"error": str(exc)}))
        elif parsed.path == "/run":
            check_id = payload.get("id")
            if check_id not in CHECK_INDEX:
                self._send(404, json.dumps({"error": f"Unknown check: {check_id}"}))
                return
            try:
                self._send(200, json.dumps(run_check(check_id, target)))
            except Exception as exc:
                self._send(400, json.dumps({"error": str(exc)}))
        else:
            self._send(404, json.dumps({"error": "Not found"}))

    def log_message(self, fmt, *args):
        sys.stdout.write("%s - %s\n" % (self.address_string(), fmt % args))


if __name__ == "__main__":
    print("World Monitor — Security Assessment API")
    print(f"Listening on http://{HOST}:{PORT}")
    print(f"Target default: {DEFAULT_TARGET}")
    print(f"Checks: {len(CHECK_INDEX)} (verified set)")
    print("Press Ctrl+C to stop.")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
