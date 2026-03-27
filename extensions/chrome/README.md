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
2. The desktop app runs an HTTP server on port 17429 for extension communication

### Chrome Installation

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **Developer mode** (toggle in top right)
3. Click **Load unpacked**
4. Select the `dist` folder from this directory

### Native Messaging Host Setup

For the extension to communicate with the desktop app, you need to install the native messaging host:

1. Get your extension ID from `chrome://extensions/` (it looks like: `abcdefghijklmnopqrstuvwxyz123456`)
2. Run the install script:
   ```bash
   ./scripts/install-native-host.sh
   ```
3. Enter your extension ID when prompted
4. Restart Chrome completely

### Firefox Installation

Firefox support is planned for a future release.

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Chrome         │     │  Native Host     │     │  PwdVault       │
│  Extension      │────▶│  (Rust binary)   │────▶│  Desktop App    │
│  (JS/HTML/CSS)  │     │  (stdio ↔ HTTP)  │     │  (HTTP :17429)  │
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

### Components

- **`background.js`**: Service worker handling native messaging and extension events
- **`content.js`**: Content script for form detection and auto-fill
- **`popup/`**: Extension popup UI for password management
- **`native-host/`**: Rust binary bridging Chrome's native messaging to HTTP

### Communication Flow

1. User clicks extension icon or triggers auto-fill
2. Extension sends message to background service worker
3. Background worker connects to native host via Chrome's native messaging API
4. Native host forwards request to desktop app via HTTP on port 17429
5. Desktop app processes request and returns response
6. Response flows back through the chain to the user

## Development

### Build Extension

```bash
./scripts/build.sh
```

### Build Native Host

```bash
cd ../native-host
cargo build --release
```

### Testing

1. Start the PwdVault desktop app
2. Load the extension in Chrome
3. Navigate to a login page
4. Test auto-fill by clicking the floating button or using the popup

## Security

- All communication happens locally on the machine
- Native messaging only allows the specific extension ID
- Passwords are only decrypted on-demand
- Master password is never transmitted

## Troubleshooting

### Extension shows "Not Connected"

1. Ensure PwdVault desktop app is running
2. Check that the HTTP server is running on port 17429
3. Verify native messaging host is installed correctly

### Auto-fill not working

1. Check if the page has a password input field
2. Try refreshing the page
3. Check browser console for errors

### Native host errors

1. Check Chrome's console at `chrome://extensions/` for error details
2. Verify the native host binary path in the manifest is correct
3. Ensure the binary has execute permissions

## File Structure

```
chrome/
├── dist/              # Built extension (load this in Chrome)
├── icons/             # Extension icons
├── manifest.json      # Chrome extension manifest
├── scripts/
│   ├── build.sh              # Build extension
│   └── install-native-host.sh # Install native messaging host
└── src/
    ├── background.js  # Service worker
    ├── content.js     # Content script
    ├── content.css    # Content styles
    └── popup/
        ├── popup.html  # Popup UI
        └── popup.js    # Popup logic
```