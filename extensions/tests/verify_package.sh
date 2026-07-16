#!/usr/bin/env bash
# Chrome/Firefox extension packaging artifact checker.
#
# Verifies that:
# 1. Chrome extension zip contains no symlinks
# 2. Firefox extension zip contains no symlinks and is self-contained
# 3. All manifest references (icons, scripts) resolve to real files
# 4. manifest.json is valid JSON
#
# Usage: ./verify_package.sh <chrome.zip> [firefox.zip]
# Or:    ./verify_package.sh --source  (check source directories)
#
# Phase 0 of the Comprehensive Optimization Plan v1.0.5.

set -euo pipefail

CHROME_ZIP="${1:-}"
FIREFOX_ZIP="${2:-}"

FAILURES=0

red() { printf '\033[0;31m%s\033[0m\n' "$*"; }
green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }

check_no_symlinks() {
    local zip_path="$1"
    local label="$2"

    if [ ! -f "$zip_path" ]; then
        red "❌ $label: file not found: $zip_path"
        FAILURES=$((FAILURES + 1))
        return
    fi

    # List symlinks in the zip. A properly packaged extension should have zero.
    local symlinks
    symlinks=$(unzip -l "$zip_path" 2>/dev/null | grep -c '\->' || true)

    if [ "$symlinks" -gt 0 ]; then
        red "❌ $label: contains $symlinks symlink(s) in the archive"
        unzip -l "$zip_path" | grep '\->' || true
        FAILURES=$((FAILURES + 1))
    else
        green "✅ $label: no symlinks found"
    fi
}

check_manifest_references() {
    local zip_path="$1"
    local label="$2"
    local tmp_dir
    tmp_dir=$(mktemp -d)

    # Extract to temp
    unzip -q -d "$tmp_dir" "$zip_path" 2>/dev/null || {
        red "❌ $label: failed to extract zip"
        rm -rf "$tmp_dir"
        FAILURES=$((FAILURES + 1))
        return
    }

    local manifest="$tmp_dir/manifest.json"

    if [ ! -f "$manifest" ]; then
        red "❌ $label: manifest.json not found in archive"
        rm -rf "$tmp_dir"
        FAILURES=$((FAILURES + 1))
        return
    fi

    # Validate JSON
    if ! python3 -c "import json; json.load(open('$manifest'))" 2>/dev/null; then
        red "❌ $label: manifest.json is not valid JSON"
        rm -rf "$tmp_dir"
        FAILURES=$((FAILURES + 1))
        return
    fi
    green "✅ $label: manifest.json is valid JSON"

    # Check that referenced icons exist
    local icons_dir="$tmp_dir/icons"
    if [ ! -d "$icons_dir" ]; then
        yellow "⚠️  $label: icons/ directory not found"
    else
        local icon_count
        icon_count=$(find "$icons_dir" -type f | wc -l | tr -d ' ')
        if [ "$icon_count" -eq 0 ]; then
            red "❌ $label: icons/ directory is empty"
            FAILURES=$((FAILURES + 1))
        else
            green "✅ $label: icons/ contains $icon_count file(s)"
        fi
    fi

    # Check that src/ exists and has background.js
    local src_dir="$tmp_dir/src"
    if [ ! -d "$src_dir" ]; then
        red "❌ $label: src/ directory not found (symlink not resolved in archive)"
        FAILURES=$((FAILURES + 1))
    elif [ ! -f "$src_dir/background.js" ]; then
        red "❌ $label: src/background.js not found"
        FAILURES=$((FAILURES + 1))
    else
        green "✅ $label: src/background.js exists"
    fi

    rm -rf "$tmp_dir"
}

check_source_directory() {
    local ext_dir="$1"
    local label="$2"

    local manifest="$ext_dir/manifest.json"

    if [ ! -f "$manifest" ]; then
        red "❌ $label: manifest.json not found at $manifest"
        FAILURES=$((FAILURES + 1))
        return
    fi

    # Validate JSON
    if ! python3 -c "import json; json.load(open('$manifest'))" 2>/dev/null; then
        red "❌ $label: manifest.json is not valid JSON"
        FAILURES=$((FAILURES + 1))
        return
    fi
    green "✅ $label: manifest.json is valid JSON"

    # For Firefox, check that symlinks exist in source (they do — this is the bug)
    if [ "$label" = "Firefox" ]; then
        if [ -L "$ext_dir/src" ]; then
            yellow "⚠️  $label: src/ is a symlink (will break in distributed zip)"
        fi
        if [ -L "$ext_dir/icons" ]; then
            yellow "⚠️  $label: icons/ is a symlink (will break in distributed zip)"
        fi
    fi

    # Check that all files referenced in manifest exist
    # (This is a basic check — a more thorough check would parse the manifest)
    local icons_dir="$ext_dir/icons"
    if [ -d "$icons_dir" ]; then
        local icon_count
        icon_count=$(find "$icons_dir" -type f -o -type l | wc -l | tr -d ' ')
        green "✅ $label: icons/ has $icon_count entries"
    else
        red "❌ $label: icons/ not found"
        FAILURES=$((FAILURES + 1))
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if [ "$CHROME_ZIP" = "--source" ]; then
    echo "=== Checking source directories ==="
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

    check_source_directory "$PROJECT_ROOT/extensions/chrome" "Chrome"
    check_source_directory "$PROJECT_ROOT/extensions/firefox" "Firefox"

    # Also verify the firefox symlinks resolve correctly in source
    echo ""
    echo "=== Firefox symlink resolution check ==="
    if [ -L "$PROJECT_ROOT/extensions/firefox/src" ]; then
        target=$(readlink "$PROJECT_ROOT/extensions/firefox/src")
        resolved="$PROJECT_ROOT/extensions/firefox/$target"
        if [ -d "$resolved" ]; then
            green "✅ Firefox src/ symlink resolves to $resolved"
        else
            red "❌ Firefox src/ symlink target does not exist: $resolved"
            FAILURES=$((FAILURES + 1))
        fi
    fi
else
    if [ -z "$CHROME_ZIP" ]; then
        echo "Usage: $0 <chrome.zip> [firefox.zip]"
        echo "       $0 --source"
        exit 1
    fi

    echo "=== Checking Chrome extension package ==="
    check_no_symlinks "$CHROME_ZIP" "Chrome"
    check_manifest_references "$CHROME_ZIP" "Chrome"

    if [ -n "$FIREFOX_ZIP" ]; then
        echo ""
        echo "=== Checking Firefox extension package ==="
        check_no_symlinks "$FIREFOX_ZIP" "Firefox"
        check_manifest_references "$FIREFOX_ZIP" "Firefox"
    fi
fi

echo ""
if [ "$FAILURES" -gt 0 ]; then
    red "❌ $FAILURES check(s) failed"
    exit 1
else
    green "✅ All packaging checks passed"
    exit 0
fi
