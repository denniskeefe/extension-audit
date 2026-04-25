from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from .report import Finding, Report, Severity

# ---------------------------------------------------------------------------
# Permission risk database
# ---------------------------------------------------------------------------

PERMISSION_RISKS: Dict[str, tuple] = {
    # CRITICAL
    "<all_urls>": (
        Severity.CRITICAL,
        "Grants read/write access to every URL the browser visits.",
        "Scope host permissions to only the domains your extension needs.",
    ),
    "nativeMessaging": (
        Severity.CRITICAL,
        "Allows the extension to communicate with native desktop apps — a full RCE bridge.",
        "Remove unless native messaging is essential and the native host is audited.",
    ),
    "debugger": (
        Severity.CRITICAL,
        "Attaches Chrome DevTools debugger to any tab — intercepts all traffic, JS, and credentials.",
        "Never ship debugger permission in production.",
    ),
    "proxy": (
        Severity.CRITICAL,
        "Can reroute all browser traffic through an attacker-controlled proxy.",
        "Remove if not core to the extension's purpose; audit proxy configuration logic.",
    ),
    # HIGH
    "cookies": (
        Severity.HIGH,
        "Read/write access to cookies across all sites (combined with host permissions).",
        "Restrict host permissions to limit which sites' cookies are accessible.",
    ),
    "history": (
        Severity.HIGH,
        "Full access to browsing history — privacy-sensitive telemetry risk.",
        "Avoid storing or transmitting history data; request only if essential.",
    ),
    "tabs": (
        Severity.HIGH,
        "Exposes tab URLs, titles, and favicon — enough to reconstruct full browsing session.",
        "Use activeTab instead of tabs where possible.",
    ),
    "webRequest": (
        Severity.HIGH,
        "Can observe all HTTP request/response headers — captures auth tokens, cookies, form data.",
        "Prefer declarativeNetRequest (MV3) over webRequest.",
    ),
    "webRequestBlocking": (
        Severity.HIGH,
        "Can block and modify requests in-flight — MITM capability at the browser level.",
        "Only use for legitimate ad-blocking or security filtering; migrate to declarativeNetRequest.",
    ),
    "declarativeNetRequest": (
        Severity.MEDIUM,
        "Can modify/block network requests via static rules.",
        "Audit included rule sets for unexpected blocking or redirects.",
    ),
    "declarativeNetRequestWithHostAccess": (
        Severity.HIGH,
        "Can redirect requests to arbitrary URLs for any site granted host access.",
        "Audit redirect rules carefully; minimize host permissions.",
    ),
    "downloads": (
        Severity.HIGH,
        "Can read download history and open/delete downloaded files.",
        "Remove if not required; ensure download paths are validated.",
    ),
    "management": (
        Severity.HIGH,
        "Can list, enable, disable, or uninstall other extensions.",
        "Remove unless this is an extension manager; extremely high abuse potential.",
    ),
    "privacy": (
        Severity.HIGH,
        "Can disable anti-tracking features (like Safe Browsing, HTTPS-Only Mode).",
        "Remove unless changing privacy settings is the extension's core function.",
    ),
    "contentSettings": (
        Severity.HIGH,
        "Can change per-site permissions (camera, microphone, JavaScript).",
        "Audit any settings modifications; changes persist after the extension is removed.",
    ),
    # MEDIUM
    "browsingData": (
        Severity.MEDIUM,
        "Can wipe cookies, cache, history, and passwords.",
        "Restrict to specific data types; show user confirmation before clearing.",
    ),
    "bookmarks": (
        Severity.MEDIUM,
        "Read/write access to all bookmarks — reveals browsing interests.",
        "Only request if bookmark functionality is core to the extension.",
    ),
    "clipboardRead": (
        Severity.MEDIUM,
        "Can silently read clipboard contents — may capture passwords or sensitive data.",
        "Use only with explicit user gesture; inform user of clipboard access.",
    ),
    "clipboardWrite": (
        Severity.MEDIUM,
        "Can silently overwrite clipboard — potential for clipboard hijacking (e.g., crypto addresses).",
        "Only write to clipboard on explicit user action.",
    ),
    "geolocation": (
        Severity.MEDIUM,
        "Access to device physical location.",
        "Remove unless location is core to the feature; always prompt the user.",
    ),
    "topSites": (
        Severity.MEDIUM,
        "Exposes the user's top-visited sites — privacy-sensitive.",
        "Remove if not needed; do not transmit to remote servers.",
    ),
    "pageCapture": (
        Severity.MEDIUM,
        "Can save any page as MHTML including its full content.",
        "Ensure captures are user-initiated and not exfiltrated.",
    ),
    "tabCapture": (
        Severity.MEDIUM,
        "Can capture tab audio and video streams.",
        "Must be user-initiated; disclose clearly in privacy policy.",
    ),
    "desktopCapture": (
        Severity.MEDIUM,
        "Can capture the screen, application windows, or tabs.",
        "Must be user-initiated; never record without explicit consent.",
    ),
    "identity": (
        Severity.MEDIUM,
        "Can retrieve Google account OAuth tokens — if exfiltrated, account takeover risk.",
        "Tokens must never be sent to third-party servers.",
    ),
    "webNavigation": (
        Severity.MEDIUM,
        "Observes all navigation events including URL and frame details.",
        "Do not log or transmit navigation events.",
    ),
    # LOW
    "storage": (Severity.LOW, "Extension local storage — low risk by itself.", None),
    "alarms": (Severity.LOW, "Schedules periodic callbacks — used for background polling.", None),
    "activeTab": (
        Severity.LOW,
        "Temporary access to the active tab on user gesture — safer alternative to 'tabs'.",
        None,
    ),
    "scripting": (
        Severity.LOW,
        "Can inject scripts into pages — verify injected code is not user-controlled.",
        "Avoid dynamic script injection with untrusted content.",
    ),
    "notifications": (Severity.LOW, "Can display system notifications.", None),
    "contextMenus": (Severity.LOW, "Adds items to the right-click menu.", None),
    "offscreen": (
        Severity.LOW,
        "Creates hidden offscreen documents — can be used to run code outside the service worker.",
        "Audit offscreen document code for data exfiltration.",
    ),
    "sidePanel": (Severity.LOW, "Renders a persistent side panel.", None),
}

WILDCARD_HOST_RE = re.compile(r"https?://\*\.")
ALL_HOST_RE = re.compile(r"<all_urls>|\*://\*/|https?://\*/")

SUSPICIOUS_UPDATE_HOSTS = {
    # Custom update URLs (not Chrome Web Store) are a supply-chain risk
    "clients2.google.com",
    "clients.google.com",
}


class ManifestAnalyzer:
    def __init__(self, ext_path: Path):
        self.ext_path = ext_path

    def analyze(self, report: Report):
        manifest_path = self.ext_path / "manifest.json"
        if not manifest_path.exists():
            report.add(Finding(
                severity=Severity.CRITICAL,
                category="Manifest",
                title="manifest.json not found",
                description="No manifest.json in extension root — cannot audit.",
                recommendation="Ensure you are pointing at the extension root directory.",
            ))
            return

        try:
            manifest: Dict[str, Any] = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            report.add(Finding(
                severity=Severity.CRITICAL,
                category="Manifest",
                title="manifest.json is invalid JSON",
                description=str(e),
                file="manifest.json",
            ))
            return

        report.metadata = {
            "name": manifest.get("name", "Unknown"),
            "version": manifest.get("version", "?"),
            "manifest_version": manifest.get("manifest_version", "?"),
            "description": manifest.get("description", ""),
        }

        mv = manifest.get("manifest_version", 2)

        self._check_permissions(manifest, report)
        self._check_host_permissions(manifest, mv, report)
        self._check_content_scripts(manifest, report)
        self._check_background(manifest, mv, report)
        self._check_csp(manifest, mv, report)
        self._check_web_accessible_resources(manifest, mv, report)
        self._check_externally_connectable(manifest, report)
        self._check_update_url(manifest, report)
        self._check_oauth2(manifest, report)
        self._check_commands(manifest, report)

    # ------------------------------------------------------------------ helpers

    def _check_permissions(self, manifest: dict, report: Report):
        all_perms: List[str] = []
        all_perms.extend(manifest.get("permissions", []))
        all_perms.extend(manifest.get("optional_permissions", []))

        for perm in all_perms:
            if perm in PERMISSION_RISKS:
                sev, desc, rec = PERMISSION_RISKS[perm]
                optional_note = " (declared as optional)" if perm in manifest.get("optional_permissions", []) else ""
                report.add(Finding(
                    severity=sev,
                    category="Permission",
                    title=f"Risky permission: {perm}{optional_note}",
                    description=desc,
                    file="manifest.json",
                    recommendation=rec,
                ))
            elif re.match(r"https?://", perm) or perm.startswith("*://"):
                self._flag_host(perm, "permissions", report)

    def _check_host_permissions(self, manifest: dict, mv: int, report: Report):
        hosts: List[str] = []
        if mv >= 3:
            hosts = manifest.get("host_permissions", [])
        else:
            hosts = [p for p in manifest.get("permissions", [])
                     if re.match(r"https?://|\*://|<all_urls>", p)]

        for host in hosts:
            self._flag_host(host, "host_permissions", report)

    def _flag_host(self, pattern: str, source: str, report: Report):
        if ALL_HOST_RE.search(pattern):
            report.add(Finding(
                severity=Severity.CRITICAL,
                category="Host Permission",
                title=f"Wildcard host access: {pattern}",
                description=f"Pattern '{pattern}' in {source} grants content-script/cookie access to every website.",
                file="manifest.json",
                recommendation="Restrict to specific domains your extension needs (e.g., https://example.com/*).",
            ))
        elif WILDCARD_HOST_RE.search(pattern):
            report.add(Finding(
                severity=Severity.MEDIUM,
                category="Host Permission",
                title=f"Broad subdomain wildcard: {pattern}",
                description=f"Pattern '{pattern}' matches all subdomains of a domain — broader than necessary.",
                file="manifest.json",
                recommendation="Lock to specific subdomains if possible.",
            ))

    def _check_content_scripts(self, manifest: dict, report: Report):
        for cs in manifest.get("content_scripts", []):
            matches = cs.get("matches", [])
            for pattern in matches:
                if ALL_HOST_RE.search(pattern):
                    report.add(Finding(
                        severity=Severity.HIGH,
                        category="Content Script",
                        title=f"Content script injected into all pages: {pattern}",
                        description="This content script runs on every website the user visits.",
                        file="manifest.json",
                        recommendation="Narrow match patterns to only the sites your extension needs.",
                    ))

            run_at = cs.get("run_at", "document_idle")
            if run_at == "document_start":
                report.add(Finding(
                    severity=Severity.LOW,
                    category="Content Script",
                    title="Content script runs at document_start",
                    description="Script executes before DOM is built — runs before page CSP is applied.",
                    file="manifest.json",
                    recommendation="Use document_idle unless document_start is required.",
                ))

            if cs.get("all_frames"):
                report.add(Finding(
                    severity=Severity.LOW,
                    category="Content Script",
                    title="Content script injected into all frames (including iframes)",
                    description="all_frames:true injects the script into every iframe on a page, including cross-origin ones.",
                    file="manifest.json",
                    recommendation="Set all_frames:false unless iframe access is required.",
                ))

    def _check_background(self, manifest: dict, mv: int, report: Report):
        if mv >= 3:
            sw = manifest.get("background", {}).get("service_worker")
            if sw:
                report.add(Finding(
                    severity=Severity.INFO,
                    category="Background",
                    title=f"Service worker: {sw}",
                    description="MV3 service worker — runs in background, limited to extension APIs.",
                    file="manifest.json",
                ))
        else:
            bg = manifest.get("background", {})
            scripts = bg.get("scripts", [])
            page = bg.get("page")
            persistent = bg.get("persistent", True)

            if persistent:
                report.add(Finding(
                    severity=Severity.MEDIUM,
                    category="Background",
                    title="Persistent background page (MV2)",
                    description="Background page runs continuously — higher attack surface and resource cost.",
                    file="manifest.json",
                    recommendation="Set persistent:false to use an event page, or migrate to MV3.",
                ))

            if scripts or page:
                targets = scripts if scripts else [page]
                report.add(Finding(
                    severity=Severity.INFO,
                    category="Background",
                    title=f"Background scripts: {', '.join(targets)}",
                    description="These scripts run with full extension privileges.",
                    file="manifest.json",
                ))

    def _check_csp(self, manifest: dict, mv: int, report: Report):
        if mv >= 3:
            csp_block = manifest.get("content_security_policy", {})
            extension_pages_csp = csp_block.get("extension_pages", "")
        else:
            extension_pages_csp = manifest.get("content_security_policy", "")

        if not extension_pages_csp:
            report.add(Finding(
                severity=Severity.LOW,
                category="CSP",
                title="No explicit content_security_policy defined",
                description="Browser defaults apply. Explicit CSP is recommended to restrict script sources.",
                file="manifest.json",
                recommendation="Add a strict content_security_policy in manifest.json.",
            ))
            return

        csp = extension_pages_csp.lower()

        unsafe_patterns = [
            ("'unsafe-eval'", "Allows eval() and dynamic code execution in extension pages."),
            ("'unsafe-inline'", "Allows inline <script> blocks in extension pages."),
            ("'unsafe-hashes'", "Weakens CSP by allowing hashes for inline event handlers."),
        ]
        for keyword, desc in unsafe_patterns:
            if keyword in csp:
                report.add(Finding(
                    severity=Severity.HIGH,
                    category="CSP",
                    title=f"Weak CSP: {keyword}",
                    description=desc,
                    file="manifest.json",
                    snippet=extension_pages_csp,
                    recommendation=f"Remove {keyword} from your CSP.",
                ))

        # Remote script sources in CSP
        remote_src = re.findall(r"https?://[^\s;'\"]+", extension_pages_csp)
        for src in remote_src:
            report.add(Finding(
                severity=Severity.HIGH,
                category="CSP",
                title=f"Remote script source in CSP: {src}",
                description=f"CSP allows loading scripts from {src} — supply chain attack surface.",
                file="manifest.json",
                recommendation="Use local scripts only; remove remote sources from CSP.",
            ))

    def _check_web_accessible_resources(self, manifest: dict, mv: int, report: Report):
        war = manifest.get("web_accessible_resources", [])
        if not war:
            return

        if mv >= 3:
            for entry in war:
                if not isinstance(entry, dict):
                    continue
                resources = entry.get("resources", [])
                matches = entry.get("matches", [])
                use_dynamic_url = entry.get("use_dynamic_url", False)

                if "<all_urls>" in matches or "*://*/*" in matches:
                    report.add(Finding(
                        severity=Severity.MEDIUM,
                        category="Web Accessible Resources",
                        title="Extension resources accessible from any website",
                        description=f"Resources {resources} can be fetched by any website — enables extension fingerprinting.",
                        file="manifest.json",
                        recommendation="Restrict matches to specific trusted origins.",
                    ))

                if "*.js" in resources or "*" in resources:
                    report.add(Finding(
                        severity=Severity.HIGH,
                        category="Web Accessible Resources",
                        title="All JS files exposed as web-accessible resources",
                        description="Exposes extension JS to web pages — logic can be fingerprinted or abused.",
                        file="manifest.json",
                        recommendation="Only expose specific files that must be web-accessible (e.g., content scripts).",
                    ))
        else:
            if "*" in war or "*.js" in war:
                report.add(Finding(
                    severity=Severity.HIGH,
                    category="Web Accessible Resources",
                    title="Broad web_accessible_resources (MV2)",
                    description="Wildcard resource exposure allows any website to load extension files.",
                    file="manifest.json",
                    recommendation="List only specific files that web pages need to load.",
                ))

    def _check_externally_connectable(self, manifest: dict, report: Report):
        ec = manifest.get("externally_connectable")
        if not ec:
            return

        matches = ec.get("matches", [])
        ids = ec.get("ids", [])

        if "*" in ids:
            report.add(Finding(
                severity=Severity.HIGH,
                category="Externally Connectable",
                title="Any extension can send messages to this extension",
                description="ids:[\"*\"] allows any installed extension to call chrome.runtime.sendMessage targeting this extension.",
                file="manifest.json",
                recommendation="List only trusted extension IDs.",
            ))

        for pattern in matches:
            if ALL_HOST_RE.search(pattern):
                report.add(Finding(
                    severity=Severity.HIGH,
                    category="Externally Connectable",
                    title=f"Any website can message this extension: {pattern}",
                    description="Broad match pattern allows arbitrary web pages to invoke extension APIs.",
                    file="manifest.json",
                    recommendation="Restrict to specific trusted origins.",
                ))

    def _check_update_url(self, manifest: dict, report: Report):
        update_url = manifest.get("update_url", "")
        if not update_url:
            return

        if "google.com" not in update_url and "gstatic.com" not in update_url:
            report.add(Finding(
                severity=Severity.HIGH,
                category="Supply Chain",
                title=f"Custom update URL: {update_url}",
                description="Extension updates from a non-Chrome-Web-Store server — supply chain risk if that server is compromised.",
                file="manifest.json",
                recommendation="Distribute through the Chrome Web Store or verify update server security.",
            ))

    def _check_oauth2(self, manifest: dict, report: Report):
        oauth2 = manifest.get("oauth2")
        if not oauth2:
            return

        scopes = oauth2.get("scopes", [])
        sensitive_scopes = [s for s in scopes if any(
            kw in s for kw in ["mail", "calendar", "contacts", "drive", "admin", "cloud", "iam"]
        )]

        if sensitive_scopes:
            report.add(Finding(
                severity=Severity.HIGH,
                category="OAuth2",
                title="Sensitive OAuth2 scopes declared",
                description=f"Extension requests these Google API scopes: {sensitive_scopes}",
                file="manifest.json",
                recommendation="Request only the minimum scopes needed; justify each scope.",
            ))
        elif scopes:
            report.add(Finding(
                severity=Severity.MEDIUM,
                category="OAuth2",
                title=f"OAuth2 scopes declared: {scopes}",
                description="Extension requests OAuth2 tokens — ensure tokens are never exfiltrated.",
                file="manifest.json",
            ))

    def _check_commands(self, manifest: dict, report: Report):
        commands = manifest.get("commands", {})
        for name, cmd in commands.items():
            suggested_key = cmd.get("suggested_key", {})
            desc = cmd.get("description", "")
            if not desc:
                report.add(Finding(
                    severity=Severity.INFO,
                    category="Commands",
                    title=f"Keyboard command '{name}' has no description",
                    description="Undescribed keyboard shortcut — users cannot identify what it does.",
                    file="manifest.json",
                    recommendation="Add a clear description to every keyboard command.",
                ))
