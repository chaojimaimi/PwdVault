# Unsigned App Installation Guide

> This guide applies to **pre-release / nightly builds** that lack a Developer
> ID code signature. Once a stable signed release is published, users do not
> need any of these steps.

## macOS

Unsigned (ad-hoc) macOS apps are blocked by Gatekeeper. After downloading the
`.dmg` and dragging PwdVault to Applications:

```bash
# Remove the quarantine attribute that triggers Gatekeeper
xattr -cr /Applications/PwdVault.app

# Launch normally
open /Applications/PwdVault.app
```

Alternatively, right-click the app → **Open** → **Open anyway** on the
Gatekeeper dialog.

### Native Messaging host

The native messaging host binary (`pwdvault-native`) bundled inside the app is
also unsigned. The desktop app auto-fixes its executable bit on launch
(`register_native_host` in `lib.rs`), but if Gatekeeper blocks it:

```bash
xattr -cr /Applications/PwdVault.app/Contents/Resources/binaries/pwdvault-native
```

## Windows

Unsigned executables trigger SmartScreen:

1. Download the `.exe` installer.
2. Run it — SmartScreen shows "Windows protected your PC".
3. Click **More info** → **Run anyway**.

This is required once per machine.

## When will signed builds be available?

Signed builds require:
- **macOS**: Apple Developer ID certificate ($99/year) — see
  [SIGNING-SETUP.md](SIGNING-SETUP.md).
- **Windows**: Authenticode code signing certificate (~$100-300/year).

Once certificates are provisioned and the GitHub Actions secrets are set,
releases will automatically be signed, notarized (macOS), and published as
stable (not pre-release).
