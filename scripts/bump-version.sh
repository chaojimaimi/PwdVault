#!/usr/bin/env bash
# bump-version.sh — Sync version across all PwdVault source files
#
# Usage: ./scripts/bump-version.sh <X.Y.Z> [--changelog]
#
# Updates VERSION, Cargo.toml, tauri.conf.json, package.json,
# and Chrome/Firefox manifest.json.
# With --changelog, prepends a new section header to CHANGELOG.md.

set -euo pipefail

# --- Validate argument ---
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <X.Y.Z> [--changelog]"
    echo "Example: $0 0.2.0 --changelog"
    exit 1
fi

V3="$1"

if ! [[ "$V3" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "ERROR: Version must match X.Y.Z format (got: $V3)"
    exit 1
fi

V4="${V3}.0"
CHANGELOG=false

if [[ "${2:-}" == "--changelog" ]]; then
    CHANGELOG=true
fi

cd "$(git -C "$(dirname "$0")" rev-parse --show-toplevel 2>/dev/null || echo "$(dirname "$0")/..")"

echo "Bumping version to $V3 (VERSION file: $V4)"

# --- Update files ---

# 1. VERSION (4-digit)
echo "$V4" > VERSION
echo "  VERSION → $V4"

# 2. src-tauri/Cargo.toml (line 3)
sed -i.bak "3s/^version = \".*\"/version = \"${V3}\"/" src-tauri/Cargo.toml && rm -f src-tauri/Cargo.toml.bak
echo "  src-tauri/Cargo.toml → $V3"

# 3. src-tauri/tauri.conf.json (line 4)
sed -i.bak "4s/\"version\": \".*\"/\"version\": \"${V3}\"/" src-tauri/tauri.conf.json && rm -f src-tauri/tauri.conf.json.bak
echo "  src-tauri/tauri.conf.json → $V3"

# 4. package.json (line 4)
sed -i.bak "4s/\"version\": \".*\"/\"version\": \"${V3}\"/" package.json && rm -f package.json.bak
echo "  package.json → $V3"

# 5. extensions/chrome/manifest.json (line 4)
sed -i.bak "4s/\"version\": \".*\"/\"version\": \"${V3}\"/" extensions/chrome/manifest.json && rm -f extensions/chrome/manifest.json.bak
echo "  extensions/chrome/manifest.json → $V3"

# 6. extensions/firefox/manifest.json (line 4)
if [[ -f extensions/firefox/manifest.json ]]; then
    sed -i.bak "4s/\"version\": \".*\"/\"version\": \"${V3}\"/" extensions/firefox/manifest.json && rm -f extensions/firefox/manifest.json.bak
    echo "  extensions/firefox/manifest.json → $V3"
fi

# --- Optional: CHANGELOG.md ---
if $CHANGELOG; then
    DATE=$(date +%Y-%m-%d)
    # Insert new section after the header block (line 6, after blank line)
    sed -i.bak "6a\\
\\
## [${V4}] - ${DATE}
" CHANGELOG.md && rm -f CHANGELOG.md.bak
    echo "  CHANGELOG.md → added [${V4}] - ${DATE}"
fi

# --- Validate ---
echo ""
echo "Validating..."
ERRORS=0

[[ "$(cat VERSION)" == "$V4" ]] || { echo "  FAIL: VERSION"; ERRORS=$((ERRORS+1)); }
grep -q "version = \"${V3}\"" src-tauri/Cargo.toml || { echo "  FAIL: src-tauri/Cargo.toml"; ERRORS=$((ERRORS+1)); }
grep -q "\"version\": \"${V3}\"" src-tauri/tauri.conf.json || { echo "  FAIL: tauri.conf.json"; ERRORS=$((ERRORS+1)); }
grep -q "\"version\": \"${V3}\"" package.json || { echo "  FAIL: package.json"; ERRORS=$((ERRORS+1)); }
grep -q "\"version\": \"${V3}\"" extensions/chrome/manifest.json || { echo "  FAIL: manifest.json"; ERRORS=$((ERRORS+1)); }
if [[ -f extensions/firefox/manifest.json ]]; then
    grep -q "\"version\": \"${V3}\"" extensions/firefox/manifest.json || { echo "  FAIL: firefox/manifest.json"; ERRORS=$((ERRORS+1)); }
fi

if [[ $ERRORS -eq 0 ]]; then
    echo "  All 6 files updated to $V3"
else
    echo "  ERRORS: $ERRORS file(s) failed validation"
    exit 1
fi
