#!/usr/bin/env python3
"""
Chrome Extension Security & Opsec Auditor
Usage: python audit.py <extension-dir|.crx|.zip> [options]
"""

from __future__ import annotations

import argparse
import io
import re
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

from analyzers.manifest import ManifestAnalyzer
from analyzers.code import CodeAnalyzer
from analyzers.html import HTMLAnalyzer
from analyzers.report import Report, Severity, _SEV_ORDER


# ---------------------------------------------------------------------------
# CRX / ZIP loading
# ---------------------------------------------------------------------------

def _extract_zip_bytes(data: bytes, dest: Path):
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        zf.extractall(dest)


CHROME_EXT_DIR = Path.home() / "Library/Application Support/Google/Chrome/Default/Extensions"
CHROME_ID_RE = re.compile(r"^[a-z]{32}$")


def resolve_chrome_id(ext_id: str) -> Path:
    ext_dir = CHROME_EXT_DIR / ext_id
    if not ext_dir.exists():
        sys.exit(f"Error: Chrome extension '{ext_id}' not found at {ext_dir}")
    versions = sorted(ext_dir.iterdir())
    if not versions:
        sys.exit(f"Error: No version directories found in {ext_dir}")
    return versions[-1]  # newest version


def load_extension(path: str) -> tuple[Path, Path | None]:
    """
    Returns (ext_path, tmp_dir).
    ext_path: directory containing manifest.json
    tmp_dir:  temporary directory to clean up, or None
    """
    if CHROME_ID_RE.match(path):
        return resolve_chrome_id(path), None

    p = Path(path)
    if not p.exists():
        sys.exit(f"Error: {path} does not exist")

    if p.is_dir():
        return p, None

    if p.suffix not in (".crx", ".zip"):
        sys.exit(f"Error: unsupported format '{p.suffix}'. Provide a directory, .crx, or .zip file.")

    raw = p.read_bytes()
    tmp = Path(tempfile.mkdtemp(prefix="ext-audit-"))

    try:
        if raw[:4] == b"Cr24":
            version = int.from_bytes(raw[4:8], "little")
            if version == 3:
                header_size = int.from_bytes(raw[8:12], "little")
                zip_start = 12 + header_size
            elif version == 2:
                pubkey_len = int.from_bytes(raw[8:12], "little")
                sig_len = int.from_bytes(raw[12:16], "little")
                zip_start = 16 + pubkey_len + sig_len
            else:
                sys.exit(f"Error: unsupported CRX version {version}")
            _extract_zip_bytes(raw[zip_start:], tmp)
        else:
            _extract_zip_bytes(raw, tmp)
    except (zipfile.BadZipFile, KeyError) as e:
        shutil.rmtree(tmp, ignore_errors=True)
        sys.exit(f"Error extracting extension: {e}")

    return tmp, tmp


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="audit.py",
        description="Chrome Extension Security & Opsec Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python audit.py fjbgpaheigpmkbdkdfghmkbnkpeofmhh         # Chrome extension ID
  python audit.py ./my-extension/                           # unpacked directory
  python audit.py extension.crx                             # .crx file
  python audit.py extension.zip --format json -o report.json
  python audit.py fjbgpaheigpmkbdkdfghmkbnkpeofmhh --min-severity high
        """,
    )
    parser.add_argument("extension", help="Extension directory, .crx/.zip file, or Chrome extension ID (32-char)")
    parser.add_argument(
        "--format", "-f",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Write report to FILE instead of stdout",
    )
    parser.add_argument(
        "--min-severity", "-s",
        choices=["critical", "high", "medium", "low", "info"],
        default="info",
        metavar="LEVEL",
        help="Minimum severity to include: critical|high|medium|low|info (default: info)",
    )
    args = parser.parse_args()

    ext_path, tmp_dir = load_extension(args.extension)

    try:
        report = Report(ext_path)

        ManifestAnalyzer(ext_path).analyze(report)
        CodeAnalyzer(ext_path).analyze(report)
        HTMLAnalyzer(ext_path).analyze(report)

        # Filter by minimum severity
        min_sev = next(s for s in _SEV_ORDER if s.name == args.min_severity.upper())
        report.filter_min_severity(min_sev)

        # Sort findings: critical first
        sev_rank = {s: i for i, s in enumerate(_SEV_ORDER)}
        report.findings.sort(key=lambda f: sev_rank[f.severity])

        output = report.to_json() if args.format == "json" else report.to_text()

        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
            print(f"Report written to {args.output}")
        else:
            print(output)

        # Exit 1 if any critical or high findings
        has_high = any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in report.findings)
        sys.exit(1 if has_high else 0)

    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
