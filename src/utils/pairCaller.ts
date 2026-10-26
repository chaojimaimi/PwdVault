/**
 * Format an extension caller label (X-PwdVault-Caller header value, v1.5.0
 * WP5) for display in the pairing toast.
 *
 * SECURITY POSITIONING: the label is derived by the native host from browser
 * process arguments, but it travels over a loopback HTTP socket where any
 * local process can forge the header — the digest shown here is a comparison
 * AID for the user (match it against chrome://extensions or about:addons),
 * NOT an authentication signal. The pairing code itself remains the secret.
 */

const CHROME_CALLER_PATTERN = /^chrome-extension:\/\/([a-p]{32})\/?$/;
const MOZ_PREFIX = "moz-extension://";

/**
 * - Chrome labels (`chrome-extension://<32 hex-ish chars a-p>/`) collapse to
 *   the ID's `前4…后4` digest, e.g. `abcd…wxyz` — short enough for a toast,
 *   long enough to disambiguate installs the user controls.
 * - Firefox labels (`moz-extension://pwdvault@pwdvault.app`) show the fixed
 *   add-on ID as-is (nothing to truncate).
 * - Anything else renders verbatim — an unknown future caller must never be
 *   mangled into a misleading digest.
 */
export function formatExtensionCaller(caller: string): string {
	const match = CHROME_CALLER_PATTERN.exec(caller);
	if (match) {
		const id = match[1];
		return `${id.slice(0, 4)}…${id.slice(-4)}`;
	}
	if (caller.startsWith(MOZ_PREFIX)) {
		return caller.slice(MOZ_PREFIX.length);
	}
	return caller;
}
