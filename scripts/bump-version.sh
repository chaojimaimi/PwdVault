#!/usr/bin/env bash
# bump-version.sh — Sync version across all PwdVault source files
#
# Usage:
#   ./scripts/bump-version.sh <X.Y.Z> [--changelog]   # bump all 10 sources
#   ./scripts/bump-version.sh --check                 # verify all sources agree
#
# Version sources (10):
#   1. VERSION
#   2. src-tauri/Cargo.toml            (main app)
#   3. src-tauri/crates/domain/Cargo.toml
#   4. src-tauri/crates/infrastructure/Cargo.toml
#   5. src-tauri/crates/application/Cargo.toml
#   6. extensions/native-host/Cargo.toml
#   7. src-tauri/tauri.conf.json
#   8. package.json
#   9. extensions/chrome/manifest.json
#  10. extensions/firefox/manifest.json
#
# The native-host protocol version (src-tauri/src/constants.rs
# NATIVE_PROTOCOL_VERSION) is intentionally separate from the product
# version per §5.6.5 and is NOT touched by this script.
#
# Exit codes:
#   0 — success (all sources in sync)
#   1 — usage error or version mismatch (--check mode)

set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Resolve repo root (works whether invoked from repo or a subdir).
repo_root() {
    git -C "$(dirname "$0")" rev-parse --show-toplevel 2>/dev/null \
        || echo "$(cd "$(dirname "$0")/.." && pwd)"
}

# Extract version from a source file. Arg 1 = source name.
read_version() {
    local root="$1"
    case "$2" in
        VERSION)
            cat "$root/VERSION" | tr -d '[:space:]' ;;
        cargo-main)
            grep '^version' "$root/src-tauri/Cargo.toml" | head -1 \
                | sed 's/version = "\(.*\)"/\1/' ;;
        cargo-host)
            grep '^version' "$root/extensions/native-host/Cargo.toml" | head -1 \
                | sed 's/version = "\(.*\)"/\1/' ;;
        cargo-domain)
            grep '^version' "$root/src-tauri/crates/domain/Cargo.toml" | head -1 \
                | sed 's/version = "\(.*\)"/\1/' ;;
        cargo-infrastructure)
            grep '^version' "$root/src-tauri/crates/infrastructure/Cargo.toml" | head -1 \
                | sed 's/version = "\(.*\)"/\1/' ;;
        cargo-application)
            grep '^version' "$root/src-tauri/crates/application/Cargo.toml" | head -1 \
                | sed 's/version = "\(.*\)"/\1/' ;;
        tauri-conf)
            python3 -c "import json; print(json.load(open('$root/src-tauri/tauri.conf.json'))['version'])" ;;
        package-json)
            python3 -c "import json; print(json.load(open('$root/package.json'))['version'])" ;;
        chrome-manifest)
            python3 -c "import json; print(json.load(open('$root/extensions/chrome/manifest.json'))['version'])" ;;
        firefox-manifest)
            python3 -c "import json; print(json.load(open('$root/extensions/firefox/manifest.json'))['version'])" ;;
        *)
            echo "ERROR: unknown source '$2'" >&2; exit 1 ;;
    esac
}

# All version source identifiers, in display order.
ALL_SOURCES=(VERSION package-json cargo-main cargo-domain cargo-infrastructure cargo-application cargo-host tauri-conf chrome-manifest firefox-manifest)

# ---------------------------------------------------------------------------
# --check mode
# ---------------------------------------------------------------------------

do_check() {
    local root
    root="$(repo_root)"
    cd "$root"

    local reference first=true errors=0
    echo "Version consistency check"
    echo "-------------------------"

    for src in "${ALL_SOURCES[@]}"; do
        local v
        v=$(read_version "$root" "$src") || { echo "  ❌ could not read $src"; errors=$((errors+1)); continue; }
        printf "  %-20s %s\n" "$src" "$v"
        if $first; then
            reference="$v"
            first=false
        elif [[ "$v" != "$reference" ]]; then
            echo "  ❌ mismatch: $src=$v, expected=$reference"
            errors=$((errors+1))
        fi
    done

    # Tag alignment: the latest git tag should match the reference version.
    local latest_tag
    latest_tag=$(git -C "$root" describe --tags --abbrev=0 2>/dev/null || echo "")
    if [[ -n "$latest_tag" ]]; then
        local tag_version="${latest_tag#v}"
        printf "  %-20s %s\n" "latest git tag" "$tag_version"
        if [[ "$tag_version" != "$reference" ]]; then
            echo "  ⚠️  latest tag ($tag_version) differs from sources ($reference) — tag the release before publishing"
            # Tag mismatch is a warning, not a hard failure (sources may be
            # bumped before the tag is pushed).
        fi
    else
        echo "  latest git tag      (none)"
    fi

    echo "-------------------------"
    if [[ $errors -eq 0 ]]; then
        echo "✅ All sources agree at $reference"
        return 0
    else
        echo "❌ $errors source(s) out of sync"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Bump mode
# ---------------------------------------------------------------------------

validate_version() {
    if ! [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "ERROR: Version must match X.Y.Z format (got: $1)" >&2
        exit 1
    fi
}

# Replace the version value on a specific line of a file.
# Uses '|' as the sed delimiter to avoid clashing with '/' in JSON/Cargo paths.
# Args: <file> <line-number> <label>
set_line_version() {
    local file="$1" line="$2" label="$3"
    # Cargo.toml uses  version = "X.Y.Z"
    # JSON files use   "version": "X.Y.Z"
    sed -i.bak -E "${line}s|\"[0-9]+\.[0-9]+\.[0-9]+\"|\"$v3\"|" "$file" && rm -f "${file}.bak"
    echo "  $label → $v3"
}

do_bump() {
    local v3="$1" want_changelog="$2"
    validate_version "$v3"

    local root
    root="$(repo_root)"
    cd "$root"

    echo "Bumping version to $v3"

    # 1. VERSION
    echo "$v3" > VERSION
    echo "  VERSION → $v3"

    # 2. src-tauri/Cargo.toml (line 3)
    set_line_version "src-tauri/Cargo.toml" 3 "src-tauri/Cargo.toml"

    # 3–5. Workspace crates (line 3)
    set_line_version "src-tauri/crates/domain/Cargo.toml" 3 "domain/Cargo.toml"
    set_line_version "src-tauri/crates/infrastructure/Cargo.toml" 3 "infrastructure/Cargo.toml"
    set_line_version "src-tauri/crates/application/Cargo.toml" 3 "application/Cargo.toml"

    # 6. extensions/native-host/Cargo.toml (line 3)
    set_line_version "extensions/native-host/Cargo.toml" 3 "native-host/Cargo.toml"

    # 7. src-tauri/tauri.conf.json (line 4)
    set_line_version "src-tauri/tauri.conf.json" 4 "tauri.conf.json"

    # 8. package.json (line 4)
    set_line_version "package.json" 4 "package.json"

    # 9. extensions/chrome/manifest.json (line 4)
    set_line_version "extensions/chrome/manifest.json" 4 "chrome/manifest.json"

    # 10. extensions/firefox/manifest.json (line 4)
    if [[ -f extensions/firefox/manifest.json ]]; then
        set_line_version "extensions/firefox/manifest.json" 4 "firefox/manifest.json"
    fi

    # Optional: prepend a CHANGELOG entry
    if $want_changelog; then
        local date
        date=$(date +%Y-%m-%d)
        # Insert a new section after the header block (line 6, after the blank line).
        sed -i.bak "6a\\
\\
## [${v3}] - ${date}
" CHANGELOG.md && rm -f CHANGELOG.md.bak
        echo "  CHANGELOG.md → added [${v3}] - ${date}"
    fi

    echo ""
    # Validate by re-reading all sources.
    do_check
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

if [[ $# -eq 1 && "$1" == "--check" ]]; then
    do_check
    exit $?
elif [[ $# -ge 1 && "$1" != "-"* ]]; then
    want_changelog=false
    if [[ "${2:-}" == "--changelog" ]]; then
        want_changelog=true
    fi
    do_bump "$1" "$want_changelog"
    exit $?
else
    echo "Usage: $0 <X.Y.Z> [--changelog]"
    echo "       $0 --check"
    echo "Example: $0 1.0.6 --changelog"
    exit 1
fi
