// Offscreen clipboard worker. Receives CLIPBOARD_CLEAR_PING from the
// background, reads the current clipboard, and only writes "" when it still
// holds the armed secret (digest match) — user content copied inside the
// window is never overwritten.

import { digestText } from "../clipboard-clear.js";

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
	if (message?.type !== "CLIPBOARD_CLEAR_PING") {
		// Not ours — stay silent so this context never wins the
		// first-response race for other broadcasts.
		return false;
	}
	verifyAndClear(message.digest)
		.then(sendResponse)
		.catch((error) =>
			sendResponse({
				cleared: false,
				reason: error?.message || "clipboard read/clear failed",
			}),
		);
	return true; // keep the channel open for the async response
});

async function verifyAndClear(expectedDigest) {
	if (typeof expectedDigest !== "string" || expectedDigest.length !== 64) {
		return { cleared: false, reason: "missing digest" };
	}
	const current = await navigator.clipboard.readText();
	if ((await digestText(current)) !== expectedDigest) {
		return { cleared: false, reason: "digest-mismatch" };
	}
	await navigator.clipboard.writeText("");
	return { cleared: true };
}
