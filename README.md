# extension-audit

Static security and opsec auditor for Chrome extensions. Analyzes unpacked extension directories, `.crx` files, and `.zip` exports.

## What it checks

**Manifest**
- Permission risk scoring (30+ permissions rated Critical → Low)
- Wildcard host permissions (`<all_urls>`, `*://*/*`)
- Content script match patterns and injection settings
- Content Security Policy weaknesses (`unsafe-eval`, `unsafe-inline`, remote sources)
- Web accessible resources exposure
- Externally connectable origins
- Custom update URLs (supply chain risk)
- OAuth2 scope sensitivity

**JavaScript**
- Dynamic code execution (`eval`, `new Function`, string-form `setTimeout`)
- Obfuscation signals (`atob`, long hex chains, `String.fromCharCode`)
- Keyloggers (keyboard event listeners)
- Password field selectors and credential harvesting
- Clipboard reads (`navigator.clipboard.readText`)
- Canvas, WebGL, and navigator fingerprinting
- WebRTC IP leak (`RTCPeerConnection`)
- Remote `importScripts()` and dynamic `<script>` injection
- Data exfiltration (`fetch`, `sendBeacon`, `WebSocket`, `XMLHttpRequest`)
- Cookie access via `chrome.cookies` API
- Sensitive data in `localStorage` (private keys, seed phrases)
- Third-party analytics and error tracking endpoints

**HTML**
- External `<script>` tags (supply chain)
- Cross-origin iframes
- Inline event handlers
- Open redirects via `document.URL` / `document.referrer`
- Meta-refresh redirects

## Install

```bash
git clone https://github.com/denniskeefe/extension-audit.git
cd extension-audit
pip install -r requirements.txt   # optional: colorama for colored output
```

## Usage

```bash
# Unpacked extension directory
python3 audit.py ./my-extension/

# .crx file (Chrome v2 and v3 supported)
python3 audit.py extension.crx

# .zip export
python3 audit.py extension.zip

# Only show high severity and above
python3 audit.py ./ext/ --min-severity high

# JSON output (for scripting or saving)
python3 audit.py ./ext/ --format json --output report.json
```

Exits with code `1` if any Critical or High findings are present — useful in CI pipelines.

## Finding installed extensions

List all installed Chrome extensions with their names and IDs:

```bash
bash list-extensions.sh
```

Then audit one:
```bash
python3 audit.py ~/Library/Application\ Support/Google/Chrome/Default/Extensions/<id>/<version>/
```

## Output example

```
======================================================================
  Chrome Extension Security Auditor
======================================================================
  Extension : My Extension
  Version   : 1.2.0
  Manifest  : v3
  Risk Score: 80/100  [CRITICAL RISK]

----------------------------------------------------------------------
  FINDINGS SUMMARY
----------------------------------------------------------------------
  [!!!] CRITICAL   2 findings
  [!! ] HIGH       5 findings
  [!  ] MEDIUM     3 findings
...
```

## Options

| Flag | Description |
|---|---|
| `--format text\|json` | Output format (default: text) |
| `--output FILE` | Write report to file instead of stdout |
| `--min-severity LEVEL` | Filter: `critical` `high` `medium` `low` `info` |
