#!/bin/bash
# Build Chrome & Firefox Extensions
# Packages the extension files into a distributable format

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXTENSION_DIR="$(dirname "$SCRIPT_DIR")"
DIST_DIR="$EXTENSION_DIR/dist"
PROJECT_ROOT="$(dirname "$(dirname "$EXTENSION_DIR")")"

echo "Building PwdVault Chrome Extension..."

# Clean dist directory
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

# Copy source files
cp -r "$EXTENSION_DIR/src"/* "$DIST_DIR/"

# Copy manifest and fix paths (src/ → ./)
cp "$EXTENSION_DIR/manifest.json" "$DIST_DIR/"
sed -i '' \
  -e 's|"service_worker": "src/|"service_worker": "|' \
  -e 's|"js": \["src/|"js": ["|' \
  -e 's|"css": \["src/|"css": ["|' \
  -e 's|"default_popup": "src/|"default_popup": "|' \
  "$DIST_DIR/manifest.json"

# Copy icons
cp -r "$EXTENSION_DIR/icons" "$DIST_DIR/"

echo "Chrome extension built successfully!"
echo "Dist: $DIST_DIR"
echo ""

# Build Firefox extension
echo "Building PwdVault Firefox Extension..."

FIREFOX_DIR="$EXTENSION_DIR/../firefox"
FIREFOX_DIST="$FIREFOX_DIR/dist"

rm -rf "$FIREFOX_DIST"
mkdir -p "$FIREFOX_DIST"

# Copy source files (follow symlinks)
cp -rL "$FIREFOX_DIR/src"/* "$FIREFOX_DIST/"

# Copy manifest and fix paths (src/ → ./)
cp "$FIREFOX_DIR/manifest.json" "$FIREFOX_DIST/"
sed -i '' \
  -e 's|"service_worker": "src/|"service_worker": "|' \
  -e 's|"js": \["src/|"js": ["|' \
  -e 's|"css": \["src/|"css": ["|' \
  -e 's|"default_popup": "src/|"default_popup": "|' \
  "$FIREFOX_DIST/manifest.json"

# Copy icons (follow symlinks)
cp -rL "$FIREFOX_DIR/icons"/* "$FIREFOX_DIST/icons/" 2>/dev/null || mkdir -p "$FIREFOX_DIST/icons" && cp -rL "$FIREFOX_DIR/icons"/* "$FIREFOX_DIST/icons/"

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
