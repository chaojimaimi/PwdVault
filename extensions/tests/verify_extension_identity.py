#!/usr/bin/env python3
"""Verify that Chrome's manifest key and desktop allowlist use one stable ID."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHROME_MANIFEST = ROOT / "extensions/chrome/manifest.json"
FIREFOX_MANIFEST = ROOT / "extensions/firefox/manifest.json"
NATIVE_SETUP = ROOT / "src-tauri/src/native_host_setup.rs"


def chrome_id(public_key_der: bytes) -> str:
    prefix = hashlib.sha256(public_key_der).digest()[:16].hex()
    return prefix.translate(str.maketrans("0123456789abcdef", "abcdefghijklmnop"))


def main() -> int:
    chrome = json.loads(CHROME_MANIFEST.read_text(encoding="utf-8"))
    firefox = json.loads(FIREFOX_MANIFEST.read_text(encoding="utf-8"))
    key = chrome.get("key")
    if not isinstance(key, str) or not key:
        raise SystemExit("Chrome manifest must contain a stable public key")
    try:
        derived_id = chrome_id(base64.b64decode(key, validate=True))
    except ValueError as error:
        raise SystemExit(f"Chrome manifest key is not valid base64: {error}") from error

    source = NATIVE_SETUP.read_text(encoding="utf-8")
    match = re.search(r'CHROME_EXTENSION_ID:\s*&str\s*=\s*"([a-p]{32})"', source)
    if not match:
        raise SystemExit("desktop stable Chrome extension ID constant is missing")
    if match.group(1) != derived_id:
        raise SystemExit(
            f"Chrome identity mismatch: manifest derives {derived_id}, desktop allows {match.group(1)}"
        )
    if "key" in firefox:
        raise SystemExit("Firefox manifest must use browser_specific_settings.gecko.id, not Chrome key")

    print(f"verified stable Chrome extension ID: {derived_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
