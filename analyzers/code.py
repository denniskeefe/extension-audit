from __future__ import annotations

import re
from pathlib import Path
from typing import List, NamedTuple, Optional

from .report import Finding, Report, Severity


class Pattern(NamedTuple):
    regex: str
    severity: Severity
    category: str
    title: str
    description: str
    recommendation: Optional[str] = None
    flags: int = re.IGNORECASE


# ---------------------------------------------------------------------------
# Pattern library
# ---------------------------------------------------------------------------

PATTERNS: List[Pattern] = [
    # ── Dynamic code execution ──────────────────────────────────────────────
    Pattern(
        r"\beval\s*\(",
        Severity.CRITICAL,
        "Dynamic Code",
        "eval() usage",
        "eval() executes arbitrary strings as code — exploitable if any part of the input is attacker-controlled.",
        "Replace with safe alternatives (JSON.parse, explicit logic).",
    ),
    Pattern(
        r"new\s+Function\s*\(",
        Severity.CRITICAL,
        "Dynamic Code",
        "new Function() constructor",
        "Equivalent to eval() — dynamically compiles and executes a string as a function body.",
        "Refactor to use explicit functions instead of dynamic construction.",
    ),
    Pattern(
        r"\bsetTimeout\s*\(\s*['\"]",
        Severity.HIGH,
        "Dynamic Code",
        "setTimeout() with string argument",
        "Passing a string to setTimeout() is equivalent to eval() — executes code from a string.",
        "Pass a function reference instead: setTimeout(() => { ... }, delay).",
    ),
    Pattern(
        r"\bsetInterval\s*\(\s*['\"]",
        Severity.HIGH,
        "Dynamic Code",
        "setInterval() with string argument",
        "Passing a string to setInterval() is equivalent to eval().",
        "Pass a function reference instead.",
    ),
    Pattern(
        r"document\.write\s*\(",
        Severity.MEDIUM,
        "Dynamic Code",
        "document.write() usage",
        "document.write() can overwrite the entire page and is a classic XSS vector.",
        "Use DOM APIs (createElement, appendChild) instead.",
    ),
    Pattern(
        r"\.innerHTML\s*=(?!=)",
        Severity.MEDIUM,
        "XSS Risk",
        "innerHTML assignment",
        "Setting innerHTML with unsanitized content causes XSS.",
        "Use textContent for text, or sanitize with DOMPurify before inserting HTML.",
    ),
    Pattern(
        r"\.outerHTML\s*=(?!=)",
        Severity.MEDIUM,
        "XSS Risk",
        "outerHTML assignment",
        "Same XSS risk as innerHTML.",
        "Use DOM APIs or sanitize content before insertion.",
    ),
    Pattern(
        r"\binsertAdjacentHTML\s*\(",
        Severity.MEDIUM,
        "XSS Risk",
        "insertAdjacentHTML() usage",
        "Inserts raw HTML into the DOM — XSS if content is user-controlled.",
        "Sanitize input with DOMPurify or use insertAdjacentText.",
    ),

    # ── Obfuscation signals ─────────────────────────────────────────────────
    Pattern(
        r"\batob\s*\(",
        Severity.MEDIUM,
        "Obfuscation",
        "Base64 decode (atob) at runtime",
        "Runtime base64 decoding is commonly used to hide strings from static analysis.",
        "Audit what is being decoded; avoid obscuring extension logic.",
    ),
    Pattern(
        r"String\.fromCharCode\s*\([^)]{40,}\)",
        Severity.HIGH,
        "Obfuscation",
        "Long String.fromCharCode() chain",
        "Constructing strings character-by-character is a common obfuscation technique.",
        "Investigate what string is being constructed and why it is hidden.",
    ),
    Pattern(
        r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){15,}",
        Severity.HIGH,
        "Obfuscation",
        "Long hex-encoded string",
        "Long sequences of hex escapes are used to hide malicious strings from scanners.",
        "Decode and audit the content of the string.",
    ),
    Pattern(
        r"\bunescape\s*\(",
        Severity.MEDIUM,
        "Obfuscation",
        "unescape() usage",
        "Deprecated function often used to decode hidden payloads.",
        "Audit what is being unescaped.",
    ),
    Pattern(
        r"(?:;|,|\{)\s*[a-zA-Z_$][a-zA-Z0-9_$]{0,2}\s*=\s*[a-zA-Z_$][a-zA-Z0-9_$]{0,2}\s*\[\s*[a-zA-Z_$][a-zA-Z0-9_$]{0,2}\s*\+\+\s*\]",
        Severity.MEDIUM,
        "Obfuscation",
        "Array-based string lookup pattern (possible obfuscation)",
        "Sequential array index lookups are a hallmark of JavaScript obfuscators (e.g., obfuscator.io).",
        "Deobfuscate the file and audit its actual behavior.",
    ),

    # ── Network / data exfiltration ─────────────────────────────────────────
    Pattern(
        r"navigator\.sendBeacon\s*\(",
        Severity.HIGH,
        "Network",
        "sendBeacon() usage",
        "sendBeacon() silently sends data to a remote server — common exfiltration technique that survives page unload.",
        "Audit the URL and data payload; ensure user consent.",
    ),
    Pattern(
        r"new\s+WebSocket\s*\(",
        Severity.HIGH,
        "Network",
        "WebSocket connection",
        "WebSockets create persistent two-way channels to remote servers — can exfiltrate data in real time.",
        "Audit the WebSocket endpoint and data sent over it.",
    ),
    Pattern(
        r"new\s+XMLHttpRequest\s*\(\s*\)",
        Severity.MEDIUM,
        "Network",
        "XMLHttpRequest usage",
        "XHR can send data to remote servers — audit the request URL and payload.",
        "Prefer fetch() with explicit CORS policy; audit all request destinations.",
    ),
    Pattern(
        r"\bfetch\s*\(\s*(?:https?://[^\s'\",)]{10}|`[^`]*https?://)",
        Severity.MEDIUM,
        "Network",
        "fetch() to external URL",
        "Data is being fetched from or sent to a remote server.",
        "Audit the URL and request body for sensitive data leakage.",
    ),
    Pattern(
        r"chrome\.cookies\.(get|getAll|set|remove)\s*\(",
        Severity.HIGH,
        "Cookie Access",
        "Programmatic cookie access",
        "Extension is reading or writing cookies via the chrome.cookies API.",
        "Ensure cookies are only accessed for the extension's stated purpose; never exfiltrate.",
    ),

    # ── Keylogging / input capture ──────────────────────────────────────────
    Pattern(
        r"addEventListener\s*\(\s*['\"]key(?:down|up|press)['\"]",
        Severity.HIGH,
        "Keylogging",
        "Keyboard event listener",
        "Listening to keyboard events on a page — potential keylogger.",
        "Ensure key capture is limited to specific UI elements and not logging sensitive input.",
    ),
    Pattern(
        r"on(?:keydown|keyup|keypress)\s*=",
        Severity.HIGH,
        "Keylogging",
        "Inline keyboard event handler",
        "Inline onkeydown/onkeyup/onkeypress — potential keylogger.",
        "Audit what keys are captured and whether they are transmitted.",
    ),

    # ── Password / form data capture ────────────────────────────────────────
    Pattern(
        r"input\[type\s*=\s*['\"]?password['\"]?\]",
        Severity.HIGH,
        "Credential Theft",
        "Password field selector",
        "Extension is selecting password input fields — high-confidence credential harvesting signal.",
        "Verify this is legitimate (e.g., a password manager); ensure values are never transmitted.",
    ),
    Pattern(
        r"\.value\b.*password|password.*\.value\b",
        Severity.HIGH,
        "Credential Theft",
        "Reading password field value",
        "Code appears to read the value of a password field.",
        "Audit whether this value is stored or transmitted.",
        re.IGNORECASE,
    ),
    Pattern(
        r"document\.(?:querySelector|getElementById|getElementsByName)\s*\([^)]*\)\s*(?:\s*\?\s*\.\s*)?\.\s*value\b",
        Severity.MEDIUM,
        "Form Data",
        "Reading form field value via DOM",
        "Extension is extracting values from page form fields.",
        "Ensure this is not harvesting user input without consent.",
    ),
    Pattern(
        r"addEventListener\s*\(\s*['\"]submit['\"]",
        Severity.MEDIUM,
        "Form Data",
        "Form submit listener",
        "Intercepting form submission events — can capture form data before it is sent.",
        "Audit what data is collected on form submit.",
    ),

    # ── Clipboard ───────────────────────────────────────────────────────────
    Pattern(
        r"navigator\.clipboard\.readText\s*\(",
        Severity.HIGH,
        "Clipboard",
        "Clipboard read (readText)",
        "Silently reads whatever is in the user's clipboard — may capture passwords, seed phrases, etc.",
        "Only read clipboard on explicit user action; disclose in privacy policy.",
    ),
    Pattern(
        r"navigator\.clipboard\.read\s*\(",
        Severity.HIGH,
        "Clipboard",
        "Clipboard read (rich content)",
        "Reads all clipboard formats including images and HTML.",
        "Only read clipboard on explicit user action; disclose in privacy policy.",
    ),
    Pattern(
        r"navigator\.clipboard\.writeText\s*\(",
        Severity.MEDIUM,
        "Clipboard",
        "Clipboard write",
        "Writes to clipboard — could be used for clipboard hijacking (e.g., substituting crypto addresses).",
        "Only write on explicit user action; validate content being written.",
    ),
    Pattern(
        r"clipboardData",
        Severity.MEDIUM,
        "Clipboard",
        "clipboardData access",
        "Accesses clipboard through drag-and-drop or cut/copy/paste events.",
        "Audit clipboard data usage.",
    ),

    # ── Fingerprinting ──────────────────────────────────────────────────────
    Pattern(
        r"(?:canvas|CanvasRenderingContext2D).*(?:toDataURL|getImageData)|(?:toDataURL|getImageData).*canvas",
        Severity.HIGH,
        "Fingerprinting",
        "Canvas fingerprinting",
        "Renders to a canvas and reads pixel data — a standard browser fingerprinting technique.",
        "Remove fingerprinting; use privacy-preserving identifiers if tracking is needed.",
        re.IGNORECASE | re.DOTALL,
    ),
    Pattern(
        r"new\s+(?:window\.)?AudioContext\s*\(",
        Severity.MEDIUM,
        "Fingerprinting",
        "AudioContext fingerprinting signal",
        "AudioContext is used in browser fingerprinting to extract device audio characteristics.",
        "Audit whether AudioContext output is being used for fingerprinting.",
    ),
    Pattern(
        r"gl\.getParameter\s*\(|WebGLRenderingContext",
        Severity.MEDIUM,
        "Fingerprinting",
        "WebGL fingerprinting signal",
        "Querying WebGL renderer/vendor strings is used for GPU-based fingerprinting.",
        "Remove if not required for extension functionality.",
    ),
    Pattern(
        r"navigator\.(?:plugins|mimeTypes)\b",
        Severity.MEDIUM,
        "Fingerprinting",
        "navigator.plugins / mimeTypes access",
        "Plugin enumeration is a classic fingerprinting vector.",
        "Remove if fingerprinting is not an intentional feature.",
    ),
    Pattern(
        r"screen\.(?:width|height|colorDepth|pixelDepth|availWidth|availHeight)",
        Severity.LOW,
        "Fingerprinting",
        "Screen dimension access",
        "Screen metrics are a fingerprinting signal when combined with other properties.",
        "Audit whether screen data is transmitted to remote servers.",
    ),
    Pattern(
        r"navigator\.(?:hardwareConcurrency|deviceMemory|platform|vendor|language)",
        Severity.LOW,
        "Fingerprinting",
        "navigator property used for fingerprinting",
        "Hardware/platform properties contribute to browser fingerprints.",
        "Audit whether these values are aggregated and transmitted.",
    ),

    # ── WebRTC IP leak ──────────────────────────────────────────────────────
    Pattern(
        r"new\s+RTCPeerConnection\s*\(",
        Severity.HIGH,
        "Opsec",
        "RTCPeerConnection — potential IP leak",
        "WebRTC peer connections can reveal the user's real IP address even behind a VPN.",
        "Disable WebRTC or set iceTransportPolicy:'relay' if VPN leak prevention is needed.",
    ),

    # ── Remote code loading ─────────────────────────────────────────────────
    Pattern(
        r"importScripts\s*\(\s*['\"]https?://",
        Severity.CRITICAL,
        "Remote Code",
        "importScripts() from remote URL",
        "Service worker is loading JavaScript from a remote server — supply chain attack vector.",
        "Bundle all scripts locally; never import from remote URLs.",
    ),
    Pattern(
        r"(?:document\.createElement|\.createElement)\s*\(\s*['\"]script['\"]\s*\)[\s\S]{0,200}\.src\s*=\s*['\"]https?://",
        Severity.CRITICAL,
        "Remote Code",
        "Dynamic <script> tag loading remote JS",
        "Injecting a script element with a remote src loads and executes code from a third-party server.",
        "Bundle all dependencies locally.",
        re.IGNORECASE | re.DOTALL,
    ),

    # ── chrome API abuse signals ────────────────────────────────────────────
    Pattern(
        r"chrome\.tabs\.(executeScript|insertCSS)\s*\(",
        Severity.MEDIUM,
        "Extension API",
        "Programmatic script/CSS injection into tabs",
        "Extension is injecting code into arbitrary tabs at runtime.",
        "Audit what is injected and under what conditions.",
    ),
    Pattern(
        r"chrome\.scripting\.executeScript\s*\(",
        Severity.MEDIUM,
        "Extension API",
        "chrome.scripting.executeScript usage (MV3)",
        "Injects and executes a script in a tab — audit the injected function and target tabs.",
        "Ensure injected logic is minimal and does not leak sensitive data.",
    ),
    Pattern(
        r"chrome\.downloads\.download\s*\(",
        Severity.MEDIUM,
        "Extension API",
        "Programmatic file download",
        "Extension can silently trigger file downloads.",
        "Ensure downloads are user-initiated and the URL/filename are validated.",
    ),
    Pattern(
        r"chrome\.management\.(setEnabled|uninstall)\s*\(",
        Severity.HIGH,
        "Extension API",
        "Modifying other extensions",
        "Extension is enabling, disabling, or uninstalling other extensions.",
        "This is almost never legitimate — remove unless this is an extension manager.",
    ),
    Pattern(
        r"chrome\.proxy\.settings\.set\s*\(",
        Severity.CRITICAL,
        "Extension API",
        "Programmatic proxy configuration",
        "Extension is changing the browser's proxy — can reroute all traffic through attacker-controlled server.",
        "Remove if not a legitimate proxy extension; disclose proxy destination to users.",
    ),
    Pattern(
        r"chrome\.privacy\.\w+\.set\s*\(",
        Severity.HIGH,
        "Extension API",
        "Modifying browser privacy settings",
        "Extension is overriding browser privacy settings (e.g., disabling Safe Browsing).",
        "Audit each privacy setting being modified.",
    ),

    # ── Sensitive data patterns ─────────────────────────────────────────────
    Pattern(
        r"(?:private[_\s]?key|mnemonic|seed[_\s]?phrase|secret[_\s]?key)",
        Severity.HIGH,
        "Sensitive Data",
        "Cryptographic key/seed phrase reference",
        "Code references private keys, mnemonics, or seed phrases — high-value exfiltration target.",
        "Ensure these values never leave the device; audit all code paths that access them.",
        re.IGNORECASE,
    ),
    Pattern(
        r"localStorage\.setItem\s*\([^,]+,\s*(?:JSON\.stringify\s*\()?\s*(?:password|token|secret|key|auth)",
        Severity.HIGH,
        "Sensitive Data",
        "Sensitive data stored in localStorage",
        "Storing secrets in localStorage is accessible to any page script — XSS leads to credential theft.",
        "Use chrome.storage.local (encrypted) or store tokens server-side with short-lived session cookies.",
        re.IGNORECASE,
    ),
    Pattern(
        r"document\.cookie\s*=",
        Severity.MEDIUM,
        "Sensitive Data",
        "Directly setting document.cookie",
        "Manipulating cookies via document.cookie — verify no sensitive data is leaked to scripts.",
        "Use HttpOnly and Secure flags; prefer chrome.cookies API.",
    ),

    # ── Tracking / analytics ────────────────────────────────────────────────
    Pattern(
        r"(?:google-analytics\.com|googletagmanager\.com|segment\.io|mixpanel\.com|amplitude\.com|hotjar\.com|fullstory\.com)",
        Severity.MEDIUM,
        "Tracking",
        "Third-party analytics/tracking domain",
        "Data is being sent to a third-party analytics service — may include browsing data.",
        "Disclose in privacy policy; ensure no PII is transmitted without consent.",
        re.IGNORECASE,
    ),
    Pattern(
        r"(?:sentry\.io|bugsnag\.com|rollbar\.com|logrocket\.com)",
        Severity.LOW,
        "Tracking",
        "Third-party error tracking service",
        "Error reports may contain stack traces with sensitive data (URLs, user state).",
        "Scrub PII from error payloads; review what data is included in reports.",
        re.IGNORECASE,
    ),
]


def _get_snippet(lines: List[str], line_no: int, context: int = 2) -> str:
    start = max(0, line_no - context - 1)
    end = min(len(lines), line_no + context)
    numbered = [f"{i + 1:4}: {lines[i]}" for i in range(start, end)]
    return "\n".join(numbered)


def _is_minified(content: str) -> bool:
    lines = content.splitlines()
    if not lines:
        return False
    avg_len = len(content) / len(lines)
    return avg_len > 500 or (len(lines) < 5 and len(content) > 5000)


class CodeAnalyzer:
    def __init__(self, ext_path: Path):
        self.ext_path = ext_path

    def analyze(self, report: Report):
        js_files = sorted(self.ext_path.rglob("*.js"))

        for js_path in js_files:
            rel = str(js_path.relative_to(self.ext_path))
            try:
                content = js_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            if _is_minified(content):
                report.add(Finding(
                    severity=Severity.MEDIUM,
                    category="Obfuscation",
                    title=f"Minified/obfuscated JS: {rel}",
                    description="File is minified or has suspiciously long lines — static analysis is limited and intent is harder to audit.",
                    file=rel,
                    recommendation="Request an un-minified source map or the original source.",
                ))

            self._scan_file(content, rel, report)

    def _scan_file(self, content: str, rel_path: str, report: Report):
        lines = content.splitlines()
        seen: dict = {}

        for pattern in PATTERNS:
            try:
                compiled = re.compile(pattern.regex, pattern.flags)
            except re.error:
                continue

            matches = list(compiled.finditer(content))
            if not matches:
                continue

            key = (rel_path, pattern.title)
            if key in seen:
                seen[key] += len(matches)
                continue
            seen[key] = len(matches)

            # Report first match with context; note count if repeated
            m = matches[0]
            line_no = content[: m.start()].count("\n") + 1
            snippet = _get_snippet(lines, line_no)

            desc = pattern.description
            if len(matches) > 1:
                desc += f" (found {len(matches)} occurrences in this file)"

            report.add(Finding(
                severity=pattern.severity,
                category=pattern.category,
                title=pattern.title,
                description=desc,
                file=rel_path,
                line=line_no,
                snippet=snippet,
                recommendation=pattern.recommendation,
            ))
