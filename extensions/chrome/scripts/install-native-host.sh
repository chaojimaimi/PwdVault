#!/bin/bash
# install-native-host.sh — Register the PwdVault native messaging host
#
# Usage: ./install-native-host.sh <chrome-extension-id> [firefox-extension-id]
#
# This script writes a config file (native-host.json) next to the PwdVault
# database so the desktop app can auto-register the NM manifest with the
# correct extension IDs on next launch.
#
# After running this script, restart the PwdVault desktop app so it picks up
# the new IDs and writes the browser manifests.

set -euo pipefail

HOST_NAME="com.pwdvault.app"

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <chrome-extension-id> [firefox-extension-id]"
    echo ""
    echo "Find your Chrome extension ID at chrome://extensions/ (enable Developer mode)."
    echo "Example: $0 abcdefghijklmnopabcdefghijklmnop"
    exit 1
fi

CHROME_ID="$1"
FIREFOX_ID="${2:-pwdvault@pwdvault.app}"

if [[ ! "$CHROME_ID" =~ ^[a-p]{32}$ ]]; then
    echo "Invalid Chrome extension ID: expected 32 lowercase letters in the range a-p" >&2
    exit 1
fi

# --- Locate the config directory (next to the vault database) ---

case "$(uname -s)" in
    Darwin*)
        CONFIG_DIR="$HOME/Library/Application Support/com.pwdvault.app"
        ;;
    Linux*)
        CONFIG_DIR="$HOME/.local/share/pwdvault"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        CONFIG_DIR="$LOCALAPPDATA/PwdVault"
        ;;
    *)
        echo "Unsupported platform: $(uname -s)"
        exit 1
        ;;
esac

mkdir -p "$CONFIG_DIR"
CONFIG_FILE="$CONFIG_DIR/native-host.json"

# --- Write the config file ---

cat > "$CONFIG_FILE" <<EOF
{
  "chrome": "$CHROME_ID",
  "firefox": "$FIREFOX_ID"
}
EOF

echo "Native host config written to: $CONFIG_FILE"
echo "  Chrome extension ID:  $CHROME_ID"
echo "  Firefox extension ID: $FIREFOX_ID"
echo ""
echo "Now restart the PwdVault desktop app to complete registration."
echo "The app will write the browser manifests on next launch."
