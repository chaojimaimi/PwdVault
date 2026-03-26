#!/bin/bash
# Install Native Messaging Host for Chrome Extension
# This script installs the native messaging host manifest

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXTENSION_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$(dirname "$EXTENSION_DIR")")"
NATIVE_HOST_DIR="$PROJECT_ROOT/extensions/native-host"
NATIVE_HOST_BINARY="$NATIVE_HOST_DIR/target/release/pwdvault-native"

# Native host name
NATIVE_HOST_NAME="com.pwdvault.app"

# Check if native host binary exists
if [ ! -f "$NATIVE_HOST_BINARY" ]; then
    echo "Building native host binary..."
    cd "$NATIVE_HOST_DIR"
    ~/.cargo/bin/cargo build --release
fi

echo "Installing PwdVault Native Messaging Host..."
echo ""

# Get extension ID from user
read -p "Enter your Chrome extension ID: " EXTENSION_ID

if [ -z "$EXTENSION_ID" ]; then
    echo "Error: Extension ID is required"
    exit 1
fi

# Determine platform-specific manifest directory
case "$(uname -s)" in
    Darwin)
        # macOS
        MANIFEST_DIR="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
        ;;
    Linux)
        # Linux
        MANIFEST_DIR="$HOME/.config/google-chrome/NativeMessagingHosts"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        # Windows (Git Bash / MSYS2)
        MANIFEST_DIR="$(cygpath -u "$LOCALAPPDATA/Google/Chrome/User Data/NativeMessagingHosts")"
        ;;
    *)
        echo "Unsupported platform: $(uname -s)"
        exit 1
        ;;
esac

# Create manifest directory if it doesn't exist
mkdir -p "$MANIFEST_DIR"

# Create manifest file
MANIFEST_FILE="$MANIFEST_DIR/$NATIVE_HOST_NAME.json"

cat > "$MANIFEST_FILE" << EOF
{
  "name": "$NATIVE_HOST_NAME",
  "description": "PwdVault Password Manager",
  "path": "$NATIVE_HOST_BINARY",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://$EXTENSION_ID/"
  ]
}
EOF

echo "Native messaging host installed!"
echo "Manifest: $MANIFEST_FILE"
echo ""
echo "Configuration:"
echo "  Extension ID: $EXTENSION_ID"
echo "  Binary: $NATIVE_HOST_BINARY"
echo ""
echo "Next steps:"
echo "1. Restart Chrome completely (quit and reopen)"
echo "2. The extension should now be able to connect to the PwdVault desktop app"