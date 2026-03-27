#!/bin/bash
# Build Chrome Extension
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

# Copy manifest
cp "$EXTENSION_DIR/manifest.json" "$DIST_DIR/"

# Copy icons
cp -r "$EXTENSION_DIR/icons" "$DIST_DIR/"

# Build native host (for development)
echo "Building native messaging host..."
cd "$EXTENSION_DIR/native-host/../../../extensions/native-host"
~/.cargo/bin/cargo build --release 2>/dev/null || true

echo "Extension built successfully!"
echo "Dist: $DIST_DIR"
echo ""
echo "To install:"
echo "1. Open Chrome and go to chrome://extensions/"
echo "2. Enable 'Developer mode'"
echo "3. Click 'Load unpacked'"
echo "4. Select: $DIST_DIR"
echo ""
echo "To install native messaging host:"
echo "1. Get your extension ID from chrome://extensions/"
echo "2. Update EXTENSION_ID in native-host manifest"
echo "3. Run: ./install-native-host.sh"