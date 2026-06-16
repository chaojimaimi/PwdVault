# PwdVault Browser Extension

Chrome/Firefox extension for PwdVault password manager.

## Features

- **Auto-fill login forms**: Detects login forms and fills credentials automatically
- **Password generator**: Generate secure random passwords
- **Context menu integration**: Right-click to fill or generate passwords
- **Keyboard shortcuts**: Quick access with Cmd/Ctrl+Shift+P
- **Floating button**: Quick access button on login pages

## Installation

### Prerequisites

1. PwdVault desktop app must be installed and running
2. The desktop app runs an HTTP server on `127.0.0.1:17429` for extension communication

### Chrome Installation

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **Developer mode** (toggle in top right)
3. Click **Load unpacked**
4. Select the `dist` folder from this directory

### Firefox Installation

1. Open Firefox and navigate to `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on**
3. Select the `firefox/dist/manifest.json` file

## Architecture

```
┌─────────────────┐                         ┌─────────────────┐
│  Chrome/Firefox │                         │  PwdVault       │
│  Extension      │──── HTTP :17429 ───────▶│  Desktop App    │
│  (JS/HTML/CSS)  │◀── HTTP :17429 ────────│  (tiny_http)    │
└─────────────────┘   (loopback only)       └─────────────────┘
```

The extension communicates directly with the desktop app over a local
HTTP API bound to `127.0.0.1:17429`. Pairing is authenticated with a
per-session Bearer token.

### Components

- **`background.js`**: Service worker handling HTTP API calls and extension events
- **`content.js`**: Content script for form detection and auto-fill
- **`popup/`**: Extension popup UI for password management

### Communication Flow

1. User clicks extension icon or triggers auto-fill
2. Extension sends message to background service worker
3. Background worker pairs with the desktop app and obtains a Bearer token
4. Background worker calls the desktop app HTTP API with the token
5. Desktop app processes request and returns response
6. Response flows back through the chain to the user

## Development

### Build Extension

```bash
./scripts/build.sh
```

### Testing

1. Start the PwdVault desktop app
2. Load the extension in Chrome
3. Navigate to a login page
4. Test auto-fill by clicking the floating button or using the popup

## Security

- All communication happens locally on the machine (loopback only)
- HTTP API is authenticated with a per-session Bearer token
- Passwords are only decrypted on-demand
- Master password is never transmitted

## Troubleshooting

### Extension shows "Not Connected"

1. Ensure PwdVault desktop app is running
2. Check that the HTTP server is running on `127.0.0.1:17429`

### Auto-fill not working

1. Check if the page has a password input field
2. Try refreshing the page
3. Check browser console for errors

## File Structure

```
chrome/
├── dist/              # Built extension (load this in Chrome)
├── icons/             # Extension icons
├── manifest.json      # Chrome extension manifest
├── scripts/
│   └── build.sh              # Build extension
└── src/
    ├── background.js  # Service worker
    ├── content.js     # Content script
    ├── content.css    # Content styles
    └── popup/
        ├── popup.html  # Popup UI
        └── popup.js    # Popup logic
```
