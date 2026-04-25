from __future__ import annotations

import re
from pathlib import Path

from .report import Finding, Report, Severity

# External URL patterns that shouldn't appear as script/link sources
EXTERNAL_SCRIPT_RE = re.compile(
    r'<script[^>]+src\s*=\s*["\']?(https?://[^"\'>\s]+)', re.IGNORECASE
)
EXTERNAL_LINK_RE = re.compile(
    r'<link[^>]+href\s*=\s*["\']?(https?://[^"\'>\s]+)', re.IGNORECASE
)
INLINE_HANDLER_RE = re.compile(
    r'\s(?:on\w+)\s*=\s*["\'][^"\']{1,}["\']', re.IGNORECASE
)
INLINE_SCRIPT_RE = re.compile(
    r'<script(?![^>]+src\s*=)[^>]*>([\s\S]*?)</script>', re.IGNORECASE
)
IFRAME_SRC_RE = re.compile(
    r'<iframe[^>]+src\s*=\s*["\']?(https?://[^"\'>\s]+)', re.IGNORECASE
)
META_REFRESH_RE = re.compile(
    r'<meta[^>]+http-equiv\s*=\s*["\']?refresh["\']?[^>]+url\s*=\s*(https?://[^\s"\'>;]+)',
    re.IGNORECASE,
)
OPEN_REDIRECT_RE = re.compile(
    r'window\.location(?:\.href)?\s*=\s*(?:location\.hash|location\.search|document\.URL|document\.referrer)',
    re.IGNORECASE,
)

KNOWN_CDNS = {
    "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com",
    "ajax.googleapis.com", "code.jquery.com", "maxcdn.bootstrapcdn.com",
    "stackpath.bootstrapcdn.com", "cdn.jsdelivr.net",
}


def _domain(url: str) -> str:
    m = re.match(r"https?://([^/]+)", url)
    return m.group(1).lower() if m else ""


class HTMLAnalyzer:
    def __init__(self, ext_path: Path):
        self.ext_path = ext_path

    def analyze(self, report: Report):
        for html_path in sorted(self.ext_path.rglob("*.html")):
            rel = str(html_path.relative_to(self.ext_path))
            try:
                content = html_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            self._scan_file(content, rel, report)

    def _scan_file(self, content: str, rel: str, report: Report):
        lines = content.splitlines()

        # ── External scripts ─────────────────────────────────────────────
        for m in EXTERNAL_SCRIPT_RE.finditer(content):
            url = m.group(1)
            domain = _domain(url)
            line_no = content[: m.start()].count("\n") + 1
            sev = Severity.HIGH if domain not in KNOWN_CDNS else Severity.MEDIUM
            report.add(Finding(
                severity=sev,
                category="Remote Code",
                title=f"External script loaded: {domain}",
                description=f"HTML page loads a JavaScript file from {url} — supply chain risk.",
                file=rel,
                line=line_no,
                snippet=lines[line_no - 1][:200] if line_no <= len(lines) else None,
                recommendation="Bundle all dependencies locally. If a CDN is required, use Subresource Integrity (SRI).",
            ))

        # ── External stylesheets / resources ────────────────────────────
        for m in EXTERNAL_LINK_RE.finditer(content):
            url = m.group(1)
            domain = _domain(url)
            line_no = content[: m.start()].count("\n") + 1
            report.add(Finding(
                severity=Severity.LOW,
                category="Remote Resource",
                title=f"External resource linked: {domain}",
                description=f"Page loads a resource from {url}. While low risk for stylesheets, it pings a third-party server.",
                file=rel,
                line=line_no,
                snippet=lines[line_no - 1][:200] if line_no <= len(lines) else None,
                recommendation="Bundle resources locally to avoid third-party pings.",
            ))

        # ── Inline event handlers ────────────────────────────────────────
        inline_matches = list(INLINE_HANDLER_RE.finditer(content))
        if inline_matches:
            line_no = content[: inline_matches[0].start()].count("\n") + 1
            count = len(inline_matches)
            report.add(Finding(
                severity=Severity.MEDIUM,
                category="CSP",
                title=f"Inline event handlers (onclick, onload, etc.) — {count} found",
                description="Inline event handlers (e.g., onclick='...') require 'unsafe-inline' in CSP, weakening security.",
                file=rel,
                line=line_no,
                snippet=inline_matches[0].group(0)[:200],
                recommendation="Move event handlers to separate JS files and attach them via addEventListener.",
            ))

        # ── Large inline scripts ─────────────────────────────────────────
        for m in INLINE_SCRIPT_RE.finditer(content):
            body = m.group(1).strip()
            if len(body) > 100:
                line_no = content[: m.start()].count("\n") + 1
                report.add(Finding(
                    severity=Severity.LOW,
                    category="CSP",
                    title="Inline <script> block in HTML",
                    description="Inline scripts require 'unsafe-inline' CSP or a nonce/hash. Also harder to audit.",
                    file=rel,
                    line=line_no,
                    snippet=body[:200] + ("..." if len(body) > 200 else ""),
                    recommendation="Move scripts to external .js files referenced via src attribute.",
                ))
                break  # one finding per file is enough

        # ── Iframes with external src ────────────────────────────────────
        for m in IFRAME_SRC_RE.finditer(content):
            url = m.group(1)
            domain = _domain(url)
            line_no = content[: m.start()].count("\n") + 1
            report.add(Finding(
                severity=Severity.MEDIUM,
                category="Iframe",
                title=f"External iframe: {domain}",
                description=f"An iframe loads content from {url}. Cross-origin iframes can perform UI redressing or exfiltrate data.",
                file=rel,
                line=line_no,
                snippet=lines[line_no - 1][:200] if line_no <= len(lines) else None,
                recommendation="Avoid cross-origin iframes; if necessary, use the sandbox attribute.",
            ))

        # ── Meta refresh redirect ────────────────────────────────────────
        for m in META_REFRESH_RE.finditer(content):
            url = m.group(1)
            line_no = content[: m.start()].count("\n") + 1
            report.add(Finding(
                severity=Severity.MEDIUM,
                category="Redirect",
                title=f"Meta-refresh redirect to: {url}",
                description="Automatic redirect to an external URL — potential phishing or open redirect.",
                file=rel,
                line=line_no,
                recommendation="Remove meta-refresh redirects; use explicit navigation with user confirmation.",
            ))

        # ── Open redirect via location ───────────────────────────────────
        for m in OPEN_REDIRECT_RE.finditer(content):
            line_no = content[: m.start()].count("\n") + 1
            report.add(Finding(
                severity=Severity.HIGH,
                category="Open Redirect",
                title="window.location set from user-controlled URL source",
                description="Setting location from document.URL, referrer, or hash can lead to open redirect/phishing.",
                file=rel,
                line=line_no,
                snippet=m.group(0)[:200],
                recommendation="Validate and whitelist any URL before navigating to it.",
            ))
