# Extension Store Publishing

> Browser extension distribution via Chrome Web Store and Firefox Add-ons
> (AMO). Store signing is the "signature" for extensions — once published,
> users install with zero friction.

## Chrome Web Store

### One-time setup

1. Register a Chrome Web Store developer account ($5 one-time fee):
   https://chrome.google.com/webstore/devconsole/
2. Create OAuth credentials for the Chrome Web Store API:
   - Google Cloud Console → APIs & Services → Enable "Chrome Web Store API"
   - Create OAuth 2.0 Client ID (type: Desktop app)
   - Complete the OAuth consent screen
3. Generate a refresh token (follow the Chrome Web Store upload API docs).
4. Add secrets to GitHub: `CHROME_CLIENT_ID`, `CHROME_CLIENT_SECRET`,
   `CHROME_REFRESH_TOKEN`, `CHROME_EXTENSION_ID`.

### Automated upload

`release.yml` includes an `Upload to Chrome Web Store` step that runs when
the Chrome secrets are present. It uploads the zip but does NOT auto-publish
(requires manual review confirmation).

### Manual upload (first time)

1. `bash extensions/chrome/scripts/build.sh`
2. Go to Chrome Web Store Developer Dashboard
3. Upload `extensions/chrome/PwdVault-Chrome-Extension-*.zip`
4. Fill in listing details, screenshots, privacy policy
5. Submit for review (typically 1-3 business days)

## Firefox Add-ons (AMO)

### One-time setup

1. Register at https://addons.mozilla.org/developers/
2. Generate API keys: Manage API Keys → Generate new key
3. Add secrets to GitHub: `AMO_API_KEY`, `AMO_API_SECRET`

### Automated signing

`release.yml` includes a `Sign for Firefox AMO` step that runs when AMO
secrets are present. Mozilla automatically signs the extension — no manual
review needed for self-distributed add-ons.

### Manual upload (first time)

1. `bash extensions/chrome/scripts/build.sh` (builds both Chrome and Firefox)
2. Go to AMO Developer Hub → Submit a New Add-on
3. Upload `extensions/firefox/PwdVault-Firefox-Extension-*.zip`
4. Fill in source code link (required for non-reviewed add-ons)
5. Submit

## Listing assets

| Asset | Status |
|-------|--------|
| Store icon 128×128 | ✅ `extensions/chrome/icons/icon128.png` |
| Screenshots | ⚠️ Needed — take from running app |
| Privacy policy URL | ⚠️ Needed — publish a page or GitHub wiki |
| Short description | ⚠️ Needed — "Secure, local-first password manager with browser autofill" |

## Version updates

Each release tag triggers `release.yml` which builds and uploads the new
extension version. The store version in `manifest.json` must match the
tag (enforced by `scripts/bump-version.sh --check`).
