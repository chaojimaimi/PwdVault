#!/usr/bin/env bash
# check-signing-secrets.sh — detect whether code signing secrets are present.
#
# Used by release.yml to decide between signed (stable) and ad-hoc (prerelease)
# builds. Outputs key=value pairs for GitHub Actions ($GITHUB_OUTPUT).
#
# Exit 0 always — the caller reads the output flags.

set -euo pipefail

MACOS_CERTS_PRESENT=false
WINDOWS_CERTS_PRESENT=false

# macOS: requires all 5 secrets to be non-empty
if [ -n "${APPLE_DEVELOPER_ID:-}" ] \
   && [ -n "${APPLE_DEVELOPER_ID_PASSWORD:-}" ] \
   && [ -n "${APPLE_ID:-}" ] \
   && [ -n "${APPLE_APP_SPECIFIC_PASSWORD:-}" ] \
   && [ -n "${APPLE_TEAM_ID:-}" ]; then
  MACOS_CERTS_PRESENT=true
fi

# Windows: requires certificate + password
if [ -n "${WINDOWS_CERTIFICATE:-}" ] && [ -n "${WINDOWS_CERTIFICATE_PASSWORD:-}" ]; then
  WINDOWS_CERTS_PRESENT=true
fi

echo "macos_certs=$MACOS_CERTS_PRESENT"
echo "windows_certs=$WINDOWS_CERTS_PRESENT"
