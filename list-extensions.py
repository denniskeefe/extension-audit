#!/usr/bin/env python3
"""List all installed Chrome extensions with their ID, name, and version."""

from __future__ import annotations

import json
import sys
from pathlib import Path


CHROME_PATHS = {
    "darwin": [
        "~/Library/Application Support/Google/Chrome",
        "~/Library/Application Support/Google/Chrome Beta",
        "~/Library/Application Support/Google/Chrome Canary",
        "~/Library/Application Support/Chromium",
    ],
    "win32": [
        "~/AppData/Local/Google/Chrome/User Data",
        "~/AppData/Local/Google/Chrome Beta/User Data",
        "~/AppData/Local/Google/Chrome SxS/User Data",
        "~/AppData/Local/Chromium/User Data",
    ],
    "linux": [
        "~/.config/google-chrome",
        "~/.config/google-chrome-beta",
        "~/.config/chromium",
        "~/snap/chromium/common/chromium",
    ],
}

PROFILES = ["Default", "Profile 1", "Profile 2", "Profile 3", "Profile 4", "Profile 5"]


def find_extension_dirs() -> list[tuple[str, Path]]:
    """Return list of (label, extensions_dir) for every Chrome profile found."""
    platform = sys.platform
    base_paths = CHROME_PATHS.get(platform, CHROME_PATHS["linux"])
    found = []

    for base in base_paths:
        base_path = Path(base).expanduser()
        if not base_path.exists():
            continue
        for profile in PROFILES:
            ext_dir = base_path / profile / "Extensions"
            if ext_dir.exists():
                label = f"{base_path.name} / {profile}"
                found.append((label, ext_dir))

    return found


def read_extension(ext_dir: Path, ext_id: str) -> dict | None:
    id_dir = ext_dir / ext_id
    if not id_dir.is_dir():
        return None

    versions = sorted(
        [d for d in id_dir.iterdir() if d.is_dir() and (d / "manifest.json").exists()]
    )
    if not versions:
        return None

    version_dir = versions[-1]
    try:
        manifest = json.loads((version_dir / "manifest.json").read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None

    name = manifest.get("name", "?")
    if name.startswith("__MSG_"):
        name = f"[{name}]"

    return {
        "id": ext_id,
        "name": name,
        "version": manifest.get("version", "?"),
        "path": str(version_dir),
    }


def main():
    profiles = find_extension_dirs()

    if not profiles:
        print("No Chrome/Chromium installation found.", file=sys.stderr)
        sys.exit(1)

    any_found = False

    for label, ext_dir in profiles:
        extensions = []
        for entry in sorted(ext_dir.iterdir()):
            if entry.name == "Temp" or not entry.is_dir():
                continue
            info = read_extension(ext_dir, entry.name)
            if info:
                extensions.append(info)

        if not extensions:
            continue

        any_found = True
        print(f"\n── {label} ({''.join(['─'] * max(0, 60 - len(label)))})")
        print(f"{'ID':<34} {'Name':<38} {'Version'}")
        print(f"{'─' * 33} {'─' * 37} {'─' * 10}")
        for ext in extensions:
            print(f"{ext['id']:<34} {ext['name'][:37]:<38} {ext['version']}")

    if not any_found:
        print("No extensions found.")


if __name__ == "__main__":
    main()
