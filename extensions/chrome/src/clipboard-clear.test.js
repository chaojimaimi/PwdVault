import { afterEach, describe, expect, it, vi } from "vitest";
import {
	ARM_STORAGE_KEY,
	CLIPBOARD_CLEAR_ALARM,
	CLIPBOARD_CLEAR_DELAY_MS,
	CLIPBOARD_CLEAR_RETRY_ALARM,
	armClipboardClear,
	createClipboardArmStorage,
	digestText,
	handleClipboardClearAlarm,
} from "./clipboard-clear.js";
import { PopupApp } from "./popup/popup.js";

const SECRET = "s3cret-password-±字符";
const OFFSCREEN_URL = "src/offscreen/clipboard.html";

function sessionArea(initial = {}) {
	const values = { ...initial };
	return {
		setAccessLevel: vi.fn().mockResolvedValue(undefined),
		get: vi.fn(async (key) => ({ [key]: values[key] })),
		set: vi.fn(async (update) => Object.assign(values, update)),
		remove: vi.fn(async (key) => delete values[key]),
	};
}

// Builds the injected deps for the clipboard-clear engine. Defaults model a
// Chrome service worker without an offscreen document yet; Firefox tests pass
// `offscreen: null` plus a `document`. The storage is always injected by the
// test (created via createClipboardArmStorage) so assertions read through the
// same public surface the background uses.
function makeDeps({
	storage,
	offscreen = { createDocument: vi.fn().mockResolvedValue(undefined) },
	getContexts,
	pingResponse = { cleared: true },
	pingError = null,
	doc = null,
} = {}) {
	const alarms = {
		create: vi.fn().mockResolvedValue(undefined),
		clear: vi.fn().mockResolvedValue(true),
	};
	const runtime = {
		sendMessage: vi.fn(async (message) => {
			if (pingError) throw pingError;
			return pingResponse;
		}),
	};
	if (getContexts !== undefined) runtime.getContexts = getContexts;
	const deps = { storage, alarms, runtime, offscreen, document: doc };
	return { deps, alarms, runtime, offscreen };
}

function firefoxFillDoc(pastedText) {
	const textarea = {
		value: "",
		style: {},
		setAttribute: vi.fn(),
		focus: vi.fn(),
		select: vi.fn(),
		remove: vi.fn(),
	};
	const execCommand = vi.fn((command) => {
		if (command === "paste") textarea.value = pastedText;
		return true;
	});
	const doc = {
		body: { appendChild: vi.fn() },
		createElement: vi.fn(() => textarea),
		execCommand,
	};
	return { doc, textarea, execCommand };
}

afterEach(() => {
	vi.restoreAllMocks();
	vi.unstubAllGlobals();
});

describe("armClipboardClear", () => {
	it("arms: writes the session record and creates the deadline alarm", async () => {
		const area = sessionArea();
		const storage = await createClipboardArmStorage({ session: area });
		const { deps, alarms } = makeDeps();
		deps.storage = storage;
		const deadline = Date.now() + CLIPBOARD_CLEAR_DELAY_MS;

		const result = await armClipboardClear(deps, {
			digest: await digestText(SECRET),
			deadline,
		});

		expect(result).toEqual({ armed: true });
		expect(storage.kind).toBe("session");
		expect(area.setAccessLevel).toHaveBeenCalledWith({
			accessLevel: "TRUSTED_CONTEXTS",
		});
		expect(area.set).toHaveBeenCalledWith({
			[ARM_STORAGE_KEY]: { digest: await digestText(SECRET), deadline },
		});
		expect(alarms.create).toHaveBeenCalledWith(CLIPBOARD_CLEAR_ALARM, {
			when: deadline,
		});
		expect(alarms.clear).toHaveBeenCalledWith(CLIPBOARD_CLEAR_RETRY_ALARM);
		expect(await storage.loadArm()).toEqual({
			digest: await digestText(SECRET),
			deadline,
		});
	});

	it("re-arming replaces the previous window (single pending semantics)", async () => {
		const storage = await createClipboardArmStorage({
			session: sessionArea(),
		});
		const { deps, alarms } = makeDeps();
		deps.storage = storage;
		const first = Date.now() + 10_000;
		const second = Date.now() + 20_000;

		await armClipboardClear(deps, { digest: "a".repeat(64), deadline: first });
		await armClipboardClear(deps, { digest: "b".repeat(64), deadline: second });

		expect(await storage.loadArm()).toEqual({
			digest: "b".repeat(64),
			deadline: second,
		});
		// The retry alarm of the previous cycle must not survive a re-arm — a
		// stale retry firing early would clear against the NEW secret.
		expect(alarms.clear).toHaveBeenCalledWith(CLIPBOARD_CLEAR_RETRY_ALARM);
	});

	it("refuses a malformed digest or an out-of-window deadline", async () => {
		const storage = await createClipboardArmStorage({
			session: sessionArea(),
		});
		const { deps, alarms } = makeDeps();
		deps.storage = storage;

		await expect(
			armClipboardClear(deps, { digest: "xyz", deadline: Date.now() + 1000 }),
		).rejects.toThrow(/digest/);
		await expect(
			armClipboardClear(deps, { digest: "a".repeat(64), deadline: 0 }),
		).rejects.toThrow(/deadline/);
		// Far-future deadlines cannot park a clipboard overwrite.
		await expect(
			armClipboardClear(deps, {
				digest: "a".repeat(64),
				deadline: Date.now() + 60 * 60_000,
			}),
		).rejects.toThrow(/deadline/);
		expect(alarms.create).not.toHaveBeenCalled();
		expect(await storage.loadArm()).toBeNull();
	});
});

describe("handleClipboardClearAlarm — Chrome offscreen path", () => {
	it("digest match → clears via the offscreen document and closes the window", async () => {
		const area = sessionArea();
		const storage = await createClipboardArmStorage({ session: area });
		const digest = await digestText(SECRET);
		const deadline = Date.now() + 100;
		const { deps, runtime, offscreen } = makeDeps();
		deps.storage = storage;
		await armClipboardClear(deps, { digest, deadline });

		const outcome = await handleClipboardClearAlarm(
			deps,
			CLIPBOARD_CLEAR_ALARM,
		);

		expect(outcome).toEqual({ cleared: true });
		expect(offscreen.createDocument).toHaveBeenCalledWith({
			url: OFFSCREEN_URL,
			reasons: ["CLIPBOARD"],
			justification: expect.any(String),
		});
		expect(runtime.sendMessage).toHaveBeenCalledWith({
			type: "CLIPBOARD_CLEAR_PING",
			digest,
		});
		// The window is done: no arm record, no failure marker.
		expect(await storage.loadArm()).toBeNull();
		expect(await storage.consumeClearFailed()).toBe(false);
	});

	it("reuses an existing offscreen document instead of recreating it", async () => {
		const storage = await createClipboardArmStorage({
			session: sessionArea(),
		});
		const { deps, offscreen } = makeDeps({
			getContexts: vi
				.fn()
				.mockResolvedValue([{ contextType: "OFFSCREEN_DOCUMENT" }]),
		});
		deps.storage = storage;

		await handleClipboardClearAlarm(deps, CLIPBOARD_CLEAR_ALARM);

		expect(offscreen.createDocument).not.toHaveBeenCalled();
	});

	it("digest mismatch (user copied something else) → never overwrites, no failure marker", async () => {
		const storage = await createClipboardArmStorage({
			session: sessionArea(),
		});
		const { deps, runtime } = makeDeps({
			pingResponse: { cleared: false, reason: "digest-mismatch" },
		});
		deps.storage = storage;
		await armClipboardClear(deps, {
			digest: await digestText(SECRET),
			deadline: Date.now() + 100,
		});

		const outcome = await handleClipboardClearAlarm(
			deps,
			CLIPBOARD_CLEAR_ALARM,
		);

		// Leaving the user's newer clipboard content alone is the intended
		// outcome, not a failure — no retry, no popup-visible marker.
		expect(outcome).toEqual({ cleared: false });
		expect(await storage.loadArm()).toBeNull();
		expect(await storage.consumeClearFailed()).toBe(false);
	});

	it("orphan alarm (record already gone) → safe skip, clipboard untouched", async () => {
		const storage = await createClipboardArmStorage({
			session: sessionArea(),
		});
		const { deps, offscreen, runtime } = makeDeps();
		deps.storage = storage;

		await handleClipboardClearAlarm(deps, CLIPBOARD_CLEAR_ALARM);

		expect(offscreen.createDocument).not.toHaveBeenCalled();
		expect(runtime.sendMessage).not.toHaveBeenCalled();
	});

	it("unknown alarm names are ignored", async () => {
		const storage = await createClipboardArmStorage({
			session: sessionArea(),
		});
		const { deps, runtime } = makeDeps();
		deps.storage = storage;

		await expect(
			handleClipboardClearAlarm(deps, "pwdvault-unrelated-alarm"),
		).resolves.toBeUndefined();
		expect(runtime.sendMessage).not.toHaveBeenCalled();
	});
});

describe("handleClipboardClearAlarm — Firefox event-page path", () => {
	function firefox_deps(storage, doc) {
		const { deps } = makeDeps({ offscreen: null, doc });
		deps.storage = storage;
		return deps;
	}

	it("paste → digest match → empty copy overwrites the clipboard", async () => {
		const storage = await createClipboardArmStorage({
			session: sessionArea(),
		});
		const { doc, textarea, execCommand } = firefoxFillDoc(SECRET);
		const deps = firefox_deps(storage, doc);
		await armClipboardClear(deps, {
			digest: await digestText(SECRET),
			deadline: Date.now() + 100,
		});

		const outcome = await handleClipboardClearAlarm(
			deps,
			CLIPBOARD_CLEAR_ALARM,
		);

		expect(outcome).toEqual({ cleared: true });
		expect(execCommand).toHaveBeenCalledWith("paste");
		expect(execCommand).toHaveBeenCalledWith("copy");
		// The overwrite copy carries the emptied textarea.
		expect(textarea.value).toBe("");
		expect(textarea.remove).toHaveBeenCalled();
		expect(await storage.loadArm()).toBeNull();
	});

	it("paste → digest mismatch → no overwrite copy", async () => {
		const storage = await createClipboardArmStorage({
			session: sessionArea(),
		});
		const { doc, execCommand, textarea } = firefoxFillDoc("user's own text");
		const deps = firefox_deps(storage, doc);
		await armClipboardClear(deps, {
			digest: await digestText(SECRET),
			deadline: Date.now() + 100,
		});

		const outcome = await handleClipboardClearAlarm(
			deps,
			CLIPBOARD_CLEAR_ALARM,
		);

		expect(outcome).toEqual({ cleared: false });
		expect(execCommand).not.toHaveBeenCalledWith("copy");
		expect(textarea.remove).toHaveBeenCalled();
		expect(await storage.loadArm()).toBeNull();
	});
});

describe("clear failure handling", () => {
	it("failure → exactly one bounded retry → still failing records the marker", async () => {
		const storage = await createClipboardArmStorage({
			session: sessionArea(),
		});
		const { deps, alarms } = makeDeps({
			pingError: new Error("offscreen document unavailable"),
		});
		deps.storage = storage;
		await armClipboardClear(deps, {
			digest: await digestText(SECRET),
			deadline: Date.now() + 100,
		});

		// First attempt fails → schedules the single retry, arm survives.
		// (create call #1 is the arm's own deadline alarm, #2 is the retry.)
		await handleClipboardClearAlarm(deps, CLIPBOARD_CLEAR_ALARM);
		expect(alarms.create).toHaveBeenCalledTimes(2);
		const [name, { when }] = alarms.create.mock.calls[1];
		expect(name).toBe(CLIPBOARD_CLEAR_RETRY_ALARM);
		expect(when).toBeGreaterThan(Date.now() + 4000);
		expect(when).toBeLessThanOrEqual(Date.now() + 6000);
		expect(await storage.loadArm()).not.toBeNull();
		expect(await storage.consumeClearFailed()).toBe(false);

		// Retry also fails → sticky marker for the popup, arm dropped.
		await handleClipboardClearAlarm(deps, CLIPBOARD_CLEAR_RETRY_ALARM);
		expect(await storage.consumeClearFailed()).toBe(true);
		expect(await storage.loadArm()).toBeNull();
	});

	it("retry succeeding closes the window without the failure marker", async () => {
		const storage = await createClipboardArmStorage({
			session: sessionArea(),
		});
		let failFirst = true;
		const { deps } = makeDeps({
			// Fail the very first ping (transient), succeed on the retry.
			pingError: null,
		});
		deps.runtime.sendMessage.mockImplementation(async () => {
			if (failFirst) throw new Error("transient");
			return { cleared: true };
		});
		deps.storage = storage;
		await armClipboardClear(deps, {
			digest: await digestText(SECRET),
			deadline: Date.now() + 100,
		});

		await handleClipboardClearAlarm(deps, CLIPBOARD_CLEAR_ALARM);
		failFirst = false;
		await handleClipboardClearAlarm(deps, CLIPBOARD_CLEAR_RETRY_ALARM);

		expect(await storage.loadArm()).toBeNull();
		expect(await storage.consumeClearFailed()).toBe(false);
	});

	it("memory fallback keeps the single-lifetime window when session is unavailable", async () => {
		const storage = await createClipboardArmStorage({});
		expect(storage.kind).toBe("memory");
		const { deps, offscreen } = makeDeps();
		deps.storage = storage;
		await armClipboardClear(deps, {
			digest: await digestText(SECRET),
			deadline: Date.now() + 100,
		});

		await handleClipboardClearAlarm(deps, CLIPBOARD_CLEAR_ALARM);

		expect(offscreen.createDocument).toHaveBeenCalled();
		expect(await storage.loadArm()).toBeNull();
	});

	it("compat branch (no getContexts) tolerates Chrome's real duplicate-creation error", async () => {
		const storage = await createClipboardArmStorage({});
		const offscreen = {
			createDocument: vi
				.fn()
				.mockRejectedValue(
					new Error(
						"Only a single offscreen document may be created per extension",
					),
				),
		};
		const { deps } = makeDeps({ offscreen }); // getContexts absent → Chrome 109–115 branch
		deps.storage = storage;
		await armClipboardClear(deps, {
			digest: await digestText(SECRET),
			deadline: Date.now() + 100,
		});

		await handleClipboardClearAlarm(deps, CLIPBOARD_CLEAR_ALARM);

		// The benign duplicate error must not fail the clear: arm consumed,
		// no failure marker written.
		expect(await storage.loadArm()).toBeNull();
		expect(await storage.consumeClearFailed()).toBe(false);
	});
});

describe("popup clipboard handoff", () => {
	// popup.js auto-instantiates at import time under the browser; under vitest
	// the module exports the class instead (import.meta.env.VITEST guard) so
	// tests drive isolated instances with a stubbed chrome.runtime.
	class TestPopup extends PopupApp {
		constructor() {
			super();
			this.toasts = [];
		}
		async init() {} // not under test
		showToast(message) {
			this.toasts.push(message);
		}
	}

	function stubChrome(sendMessage) {
		vi.stubGlobal("chrome", { runtime: { sendMessage } });
		return sendMessage;
	}

	function stubClipboardWrite() {
		const writeText = vi.fn().mockResolvedValue(undefined);
		Object.defineProperty(navigator, "clipboard", {
			value: { writeText },
			configurable: true,
		});
		return writeText;
	}

	it("arm accepted → toast promises the 30s auto-clear with the right payload", async () => {
		const send = stubChrome(vi.fn().mockResolvedValue({ armed: true }));
		stubClipboardWrite();
		const app = new TestPopup();

		await app.copyToClipboard(SECRET, "Password copied!", true);

		expect(app.toasts).toEqual(["Password copied! (auto-clears in 30s)"]);
		const [message] = send.mock.calls.at(-1);
		expect(message.type).toBe("CLIPBOARD_ARM_CLEAR");
		expect(message.digest).toBe(await digestText(SECRET));
		// The deadline carries the same 30s window as the toast promise.
		expect(message.deadline).toBeGreaterThan(Date.now() + 29_000);
		expect(message.deadline).toBeLessThanOrEqual(Date.now() + 31_000);
	});

	it("arm refused → plain copied toast, no promised clear, warning logged", async () => {
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		stubChrome(vi.fn().mockRejectedValue(new Error("sw unreachable")));
		stubClipboardWrite();
		const app = new TestPopup();

		await app.copyToClipboard(SECRET, "Password copied!", true);

		expect(app.toasts).toEqual(["Password copied!"]);
		expect(warn).toHaveBeenCalledWith(
			"PwdVault: clipboard auto-clear arm failed:",
			expect.any(Error),
		);
	});

	it("arm payload rejected by the engine (bad deadline) degrades to the plain toast", async () => {
		// The background validates the arm; a hostile/buggy response shape must
		// not make the popup promise a clear that was never scheduled.
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		stubChrome(vi.fn().mockResolvedValue({ armed: "yes" }));
		stubClipboardWrite();
		const app = new TestPopup();

		await app.copyToClipboard(SECRET, "Password copied!", true);

		expect(app.toasts).toEqual(["Password copied!"]);
		expect(warn).not.toHaveBeenCalled(); // not an error — an unfulfilled promise
	});

	it("failure marker is consumed exactly once across popup opens", async () => {
		let consumed = false;
		const send = stubChrome(
			vi.fn(async (message) => {
				if (message.type === "CONSUME_CLIPBOARD_CLEAR_FAILURE") {
					if (consumed) return { failed: false };
					consumed = true;
					return { failed: true };
				}
				return { armed: true };
			}),
		);
		stubClipboardWrite();

		// First popup open after the failed clear: toasts once.
		const first = new TestPopup();
		await first.consumeClipboardClearFailure();
		expect(first.toasts).toEqual(["Previous clipboard auto-clear failed"]);

		// Second open: the marker is gone — notify-once, like the desktop.
		const second = new TestPopup();
		await second.consumeClipboardClearFailure();
		expect(second.toasts).toEqual([]);
		expect(send).toHaveBeenCalledTimes(2);
	});
});
