import { describe, expect, it, vi } from "vitest";
import { PopupApp } from "./popup.js";

// v1.8.4 P3-11: goToUrl must never open a tab or close the popup with a
// URL the parser rejects. PopupApp is exported (auto-init skipped) under
// vitest exactly so tests can drive isolated instances (see the export
// guard in popup.js); goToUrl touches only chrome.tabs and window.close,
// so a bare prototype instance plus two spies is the whole harness.
function makeApp(tabsCreate) {
	globalThis.chrome = {
		...(globalThis.chrome || {}),
		tabs: { create: tabsCreate },
	};
	const close = vi.spyOn(window, "close").mockImplementation(() => {});
	return {
		app: Object.create(PopupApp.prototype),
		close,
	};
}

describe("popup goToUrl validation (v1.8.4 P3-11)", () => {
	it("does not open a tab or close the window for a URL that cannot parse", async () => {
		const tabsCreate = vi.fn();
		const { app, close } = makeApp(tabsCreate);
		// "javascript:alert(1)" becomes https://javascript:alert(1) under the
		// prepend rule — an invalid port; "http://" has an empty host. Both
		// genuinely throw in new URL.
		await app.goToUrl("javascript:alert(1)");
		await app.goToUrl("http://");
		expect(tabsCreate).not.toHaveBeenCalled();
		expect(close).not.toHaveBeenCalled();
		close.mockRestore();
	});

	it("still opens a well-formed URL in a new tab and closes the popup", async () => {
		const tabsCreate = vi.fn();
		const { app, close } = makeApp(tabsCreate);
		await app.goToUrl("example.com");
		expect(tabsCreate).toHaveBeenCalledWith({ url: "https://example.com" });
		expect(close).toHaveBeenCalled();
		close.mockRestore();
	});
});
