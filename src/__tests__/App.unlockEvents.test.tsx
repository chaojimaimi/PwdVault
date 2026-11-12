import { render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// v1.5.0 (WP3/WP5): the native-event toast hook. The Rust adapters emit
// `trash-auto-purged(count)` after a post-unlock sweep (never for 0 — that
// guard lives adapter-side in unlock_effects.rs) and `pair-request` with a
// { code, caller } payload; this pins the frontend's consumption — toast
// copy, caller digest rendering, and pair payload shape.

type ListenHandler = (event: { payload: unknown }) => void;

const listeners = new Map<string, ListenHandler>();

vi.mock("@tauri-apps/api/event", () => ({
	listen: (eventName: string, handler: ListenHandler) => {
		listeners.set(eventName, handler);
		return Promise.resolve(vi.fn());
	},
}));

describe("useNativeEventToasts", () => {
	beforeEach(() => {
		listeners.clear();
	});

	afterEach(() => {
		document.getElementById("toast-container")?.remove();
		vi.resetModules();
	});

	async function mountHook() {
		const { useNativeEventToasts } = await import("../App");
		function Harness() {
			useNativeEventToasts();
			return null;
		}
		return render(<Harness />);
	}

	it("shows a trash purge toast with the emitted count", async () => {
		await mountHook();
		listeners.get("trash-auto-purged")?.({ payload: 12 });
		expect(document.body.textContent).toContain(
			"Trash auto-purged 12 item(s)",
		);
	});

	// v1.8.4 (P2-6): the sweep can fail (locked session, backend error) —
	// the Rust side emits the sanitized public message; the frontend renders
	// it as a long-lived error toast so device divergence stays visible.
	it("shows an error toast when the trash auto-purge fails", async () => {
		await mountHook();
		listeners.get("trash-purge-failed")?.({
			payload: "Vault is locked",
		});
		const toast = document.querySelector(".toast-error");
		expect(toast).not.toBeNull();
		expect(toast?.getAttribute("role")).toBe("alert");
		expect(document.body.textContent).toContain(
			"Trash auto-purge failed: Vault is locked",
		);
	});

	it("shows the pairing toast with the caller digest row", async () => {
		await mountHook();
		listeners.get("pair-request")?.({
			payload: {
				code: "123456",
				caller: "chrome-extension://abcdefghijklmnopabcdefghijklmnop/",
			},
		});
		expect(document.body.textContent).toContain("123 456");
		expect(document.body.textContent).toContain("请求方：abcd…mnop");
		expect(document.body.textContent).toContain("非身份认证");
	});

	it("still pairs when the payload carries no caller (defensive)", async () => {
		await mountHook();
		listeners.get("pair-request")?.({ payload: { code: "654321" } });
		expect(document.body.textContent).toContain("654 321");
		expect(document.body.textContent).not.toContain("请求方");
	});
});
