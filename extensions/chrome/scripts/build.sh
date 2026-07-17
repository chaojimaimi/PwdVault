#!/usr/bin/env bash
# Build Chrome & Firefox Extensions
# Packages the extension files into a distributable format

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXTENSION_DIR="$(dirname "$SCRIPT_DIR")"
DIST_DIR="$EXTENSION_DIR/dist"
PROJECT_ROOT="$(dirname "$(dirname "$EXTENSION_DIR")")"

python3 "$PROJECT_ROOT/extensions/tests/verify_extension_identity.py"

echo "Building PwdVault Chrome Extension..."

# Clean dist directory
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

# Preserve the source layout used by manifest.json. This avoids platform-
# specific sed invocations and makes local packages identical to CI packages.
cp -R "$EXTENSION_DIR/src" "$DIST_DIR/src"
cp "$EXTENSION_DIR/manifest.json" "$DIST_DIR/"

# Copy icons
cp -R "$EXTENSION_DIR/icons" "$DIST_DIR/icons"

echo "Chrome extension built successfully!"
echo "Dist: $DIST_DIR"
echo ""

# Build Firefox extension
echo "Building PwdVault Firefox Extension..."

FIREFOX_DIR="$EXTENSION_DIR/../firefox"
FIREFOX_DIST="$FIREFOX_DIR/dist"

rm -rf "$FIREFOX_DIST"
mkdir -p "$FIREFOX_DIST"

# Dereference shared source into a self-contained staging directory.
cp -RL "$FIREFOX_DIR/src" "$FIREFOX_DIST/src"
cp "$FIREFOX_DIR/manifest.json" "$FIREFOX_DIST/"
cp -RL "$FIREFOX_DIR/icons" "$FIREFOX_DIST/icons"

python3 "$PROJECT_ROOT/extensions/tests/verify_manifest.py" "$DIST_DIR"
python3 "$PROJECT_ROOT/extensions/tests/verify_manifest.py" "$FIREFOX_DIST"

echo "Firefox extension built successfully!"
echo "Dist: $FIREFOX_DIST"
echo ""

echo ""
echo "All extensions built!"
echo ""
echo "Chrome install:"
echo "1. Open chrome://extensions/ → Enable Developer mode → Load unpacked → $DIST_DIR"
echo ""
echo "Firefox install:"
echo "1. Open about:debugging#/runtime/this-firefox → Load Temporary Add-on → $FIREFOX_DIST/manifest.json"
