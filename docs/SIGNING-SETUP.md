# Code Signing Setup Guide

> This document describes how to provision code signing certificates and
> configure the GitHub Actions secrets that enable signed stable releases.
> Once these secrets are in place, `release.yml` automatically signs,
> notarizes, and publishes stable builds — no code changes required.

## Required GitHub Actions secrets

### macOS (all 5 required)

| Secret name | How to obtain |
|-------------|---------------|
| `APPLE_DEVELOPER_ID` | Developer ID Application certificate exported as p12, base64-encoded: `base64 -i developer-id.p12` |
| `APPLE_DEVELOPER_ID_PASSWORD` | Password used when exporting the p12 |
| `APPLE_ID` | Apple Developer account email |
| `APPLE_APP_SPECIFIC_PASSWORD` | Generated at appleid.apple.com → Sign-In & Security → App-Specific Passwords |
| `APPLE_TEAM_ID` | Found in Apple Developer → Membership → Team ID (10-char alphanumeric) |

### Windows (both required)

| Secret name | How to obtain |
|-------------|---------------|
| `WINDOWS_CERTIFICATE` | Authenticode certificate pfx, base64-encoded: `base64 -i cert.pfx` (Linux/macOS) or `certutil -encode cert.pfx cert.b64` (Windows) |
| `WINDOWS_CERTIFICATE_PASSWORD` | Password for the pfx file |

### Browser extensions (optional)

| Secret name | How to obtain |
|-------------|---------------|
| `CHROME_CLIENT_ID` / `CHROME_CLIENT_SECRET` / `CHROME_REFRESH_TOKEN` | Google Cloud Console → Create OAuth credentials for Chrome Web Store API |
| `CHROME_EXTENSION_ID` | The extension ID assigned by Chrome Web Store after first upload |
| `AMO_API_KEY` / `AMO_API_SECRET` | Firefox AMO → Manage API Keys (addons.mozilla.org/developers/) |

## Step-by-step: macOS

1. Enroll in [Apple Developer Program](https://developer.apple.com/programs/) ($99/year).
2. Request a **Developer ID Application** certificate in Certificates, Identifiers & Profiles.
3. Export the certificate + private key as a `.p12` file from Keychain Access.
4. Base64-encode: `base64 -i developer-id-application.p12 | pbcopy`
5. Add all 5 secrets to GitHub repo → Settings → Secrets and variables → Actions.

## Step-by-step: Windows

1. Purchase an Authenticode code signing certificate (EV recommended) from
   DigiCert, Sectigo, or similar.
2. Export as `.pfx`.
3. Base64-encode (on macOS/Linux): `base64 -i cert.pfx | pbcopy`
4. Add both secrets to GitHub.

## Verification

After adding secrets, push a tag to trigger release.yml. The workflow will:
- Detect secrets via `scripts/check-signing-secrets.sh`
- If all present: sign, notarize, staple, verify → stable release
- If missing: ad-hoc sign → prerelease (see UNSIGNED-INSTALL.md)
