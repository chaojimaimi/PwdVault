import { describe, expect, it, beforeAll } from "vitest";

// v1.6.0 WP4 behavioral test: drives the REAL background.js onMessage
// listener with a stubbed chrome namespace and a scripted native-messaging
// host. The source-text contract in content-save-prompt.test.js pins the
// plaintext boundaries; this file pins the DECISION LOGIC and wire shapes
// that source text cannot — the save/update/none verdicts, the serial
// short-circuit, the session-sticky unknown-command degradation, and the
// whole-replace update_entry echo (the desktop replaces title/url/tags/
// group/mode wholesale, so omitting the echo would wipe them).
const nmCalls = [];
let verifyResponses = []; // queue of {matches} or {error} per verify call
let nmScript = null;

const messageListener = { fn: null };

globalThis.chrome = {
	runtime: {
		id: "test-runtime-id",
		lastError: null,
		onMessage: { addListener: (fn) => (messageListener.fn = fn) },
		onInstalled: { addListener: () => {} },
		onStartup: { addListener: () => {} },
		sendNativeMessage: (host, msg, cb) => {
			nmCalls.push(msg);
			if (msg.command === "handshake") {
				cb({ id: 0, success: true, data: { protocol_version: 1 } });
				return;
			}
			if (msg.command === "pair") {
				cb({ id: 0, success: true, data: { token: "tok-123" } });
				return;
			}
			if (msg.command === "verify_entry_password") {
				const next = verifyResponses.shift() || { matches: true };
				if (next.error !== undefined) {
					cb({ id: 0, success: false, error: next.error });
					return;
				}
				cb({ id: 0, success: true, data: { matches: next.matches } });
				return;
			}
			if (nmScript && nmScript[msg.command]) {
				cb({ id: 0, success: true, data: nmScript[msg.command](msg) });
				return;
			}
			cb({ id: 0, success: false, error: "Unknown command" });
		},
	},
	storage: {
		session: {
			get: async () => ({}),
			set: async () => {},
			remove: async () => {},
		},
	},
	alarms: { onAlarm: { addListener: () => {} }, create: () => {} },
	commands: { onCommand: { addListener: () => {} } },
	contextMenus: {
		removeAll: (cb) => cb && cb(),
		create: () => {},
		onClicked: { addListener: () => {} },
	},
	tabs: { query: async () => [], sendMessage: () => {} },
};

const contentSender = {
	id: "test-runtime-id",
	tab: { url: "https://example.com/login" },
};
const popupSender = {
	id: "test-runtime-id",
	url: "chrome-extension://test-runtime-id/src/popup/popup.html",
};

function send(message, sender = contentSender) {
	return new Promise((resolve, reject) => {
		messageListener.fn(message, sender, (response) => {
			if (response && response.error) reject(new Error(response.error));
			else resolve(response);
		});
	});
}

const sendSoft = (message, sender = contentSender) =>
	new Promise((resolve) => {
		messageListener.fn(message, sender, resolve);
	});

beforeAll(async () => {
	await import("./background.js");
	if (!messageListener.fn) throw new Error("onMessage listener not registered");
	// Pair first so apiToken exists for authenticated commands.
	await send({ type: "START_PAIRING" }, popupSender);
});

describe("save-prompt background behavior (smoke)", () => {
	it("pairing succeeded", () => {
		expect(nmCalls.some((m) => m.command === "pair")).toBe(true);
	});

	it("no candidates decides save", async () => {
		nmCalls.length = 0;
		const res = await send({
			type: "CHECK_SAVE_CREDENTIALS",
			password_sha256: "a".repeat(64),
			candidates: [],
		});
		expect(res).toEqual({ action: "save" });
		expect(nmCalls.filter((m) => m.command === "verify_entry_password")).toHaveLength(0);
	});

	it("first non-matching candidate decides update with its title", async () => {
		nmCalls.length = 0;
		verifyResponses = [{ matches: true }, { matches: false }];
		const res = await send({
			type: "CHECK_SAVE_CREDENTIALS",
			password_sha256: "a".repeat(64),
			candidates: [
				{ id: "e1", title: "First", username: "u" },
				{ id: "e2", title: "Second", username: "u" },
			],
		});
		expect(res).toEqual({
			action: "update",
			entry_id: "e2",
			entry_title: "Second",
		});
		// Serial short-circuit: exactly 2 verify calls, in candidate order.
		const verifies = nmCalls.filter((m) => m.command === "verify_entry_password");
		expect(verifies).toHaveLength(2);
		expect(verifies[0].id_param).toBe("e1");
		expect(verifies[1].id_param).toBe("e2");
		expect(verifies[0].password_sha256).toBe("a".repeat(64));
	});

	it("all matching candidates decide none silently", async () => {
		verifyResponses = [{ matches: true }, { matches: true }];
		const res = await send({
			type: "CHECK_SAVE_CREDENTIALS",
			password_sha256: "a".repeat(64),
			candidates: [
				{ id: "e1", title: "First", username: "u" },
				{ id: "e2", title: "Second", username: "u" },
			],
		});
		expect(res).toEqual({ action: "none" });
	});

	it("a locked vault surfaces an error (content stays silent)", async () => {
		verifyResponses = [{ error: "Vault is locked" }];
		const res = await sendSoft({
			type: "CHECK_SAVE_CREDENTIALS",
			password_sha256: "a".repeat(64),
			candidates: [{ id: "e1", title: "First", username: "u" }],
		});
		expect(res.error).toMatch(/locked/i);
	});

	it("an unknown command degrades to none and sticks for the session", async () => {
		verifyResponses = [{ error: "Unknown command" }];
		const first = await send({
			type: "CHECK_SAVE_CREDENTIALS",
			password_sha256: "a".repeat(64),
			candidates: [{ id: "e1", title: "First", username: "u" }],
		});
		expect(first).toEqual({ action: "none" });
		nmCalls.length = 0;
		const second = await send({
			type: "CHECK_SAVE_CREDENTIALS",
			password_sha256: "b".repeat(64),
			candidates: [{ id: "e1", title: "First", username: "u" }],
		});
		expect(second).toEqual({ action: "none" });
		// Degraded: no further verify round-trips at all.
		expect(nmCalls.filter((m) => m.command === "verify_entry_password")).toHaveLength(0);
	});

	it("create-mode confirm derives the title from the URL hostname", async () => {
		let captured = null;
		nmScript = {
			create_entry: (msg) => {
				captured = msg;
				return { id: "new-1", title: msg.title };
			},
		};
		const res = await send({
			type: "SAVE_LOGIN_CONFIRMED",
			mode: "create",
			url: "https://accounts.example.com/signup?x=1",
			username: "user@x.com",
			password: "secret-1",
		});
		expect(res).toEqual({ ok: true });
		expect(captured.title).toBe("accounts.example.com");
		expect(captured.username).toBe("user@x.com");
		expect(captured.password).toBe("secret-1");
		expect(captured.tags).toEqual([]);
		expect(captured.group_id).toBeNull();
	});

	it("update-mode confirm echoes entry metadata and only re-keys the password", async () => {
		let captured = null;
		nmScript = {
			update_entry: (msg) => {
				captured = msg;
				return { id: msg.id_param };
			},
		};
		const res = await send({
			type: "SAVE_LOGIN_CONFIRMED",
			mode: "update",
			entry_id: "e2",
			url: "https://example.com/login",
			username: "user@x.com",
			password: "new-secret",
			entry: {
				title: "Second",
				username: "user@x.com",
				url: "https://example.com/account",
				tags: ["work"],
				group_id: "g1",
				url_match_mode: "domain",
			},
		});
		expect(res).toEqual({ ok: true });
		expect(captured.id_param).toBe("e2");
		expect(captured.title).toBe("Second");
		expect(captured.username).toBe("user@x.com");
		expect(captured.url).toBe("https://example.com/account");
		expect(captured.tags).toEqual(["work"]);
		expect(captured.group_id).toBe("g1");
		expect(captured.url_match_mode).toBe("domain");
		expect(captured.password).toBe("new-secret");
		// Tri-state omissions: notes/custom_fields untouched, no totp surface.
		expect("notes" in captured).toBe(false);
		expect("custom_fields" in captured).toBe(false);
		expect("totp_secret" in captured).toBe(false);
	});

	it("an unknown match mode degrades to omit (desktop default Auto)", async () => {
		let captured = null;
		nmScript = {
			update_entry: (msg) => {
				captured = msg;
				return { id: msg.id_param };
			},
		};
		await send({
			type: "SAVE_LOGIN_CONFIRMED",
			mode: "update",
			entry_id: "e2",
			url: "https://example.com/login",
			username: "u",
			password: "p",
			entry: { title: "T", username: "u", url: null, tags: [], group_id: null, url_match_mode: "weird" },
		});
		expect(captured.url_match_mode).toBeUndefined();
		expect(captured.url).toBeNull();
	});

	it("a failed create surfaces the desktop error", async () => {
		// nmScript=null → the stub host answers "Unknown command" for
		// create_entry → sendToApp throws → the listener catch maps it to
		// {error} for the content toast.
		nmScript = null;
		const res = await sendSoft({
			type: "SAVE_LOGIN_CONFIRMED",
			mode: "create",
			url: "https://example.com/",
			username: "u",
			password: "p",
		});
		expect(res.error).toBeTruthy();
	});

	it("a malformed update payload fails closed without an update_entry call", async () => {
		// The update whole-replaces the entry metadata: a payload without it
		// (or without the entry_id address) must be rejected client-side —
		// never forwarded to the desktop where it could blank stored fields.
		let captured = null;
		nmScript = {
			update_entry: (msg) => {
				captured = msg;
				return { id: msg.id_param };
			},
		};

		const noMeta = await sendSoft({
			type: "SAVE_LOGIN_CONFIRMED",
			mode: "update",
			entry_id: "e1",
			url: "https://example.com/login",
			username: "u",
			password: "p",
		});
		expect(noMeta.error).toMatch(/entry metadata/i);
		expect(captured).toBeNull();

		const noId = await sendSoft({
			type: "SAVE_LOGIN_CONFIRMED",
			mode: "update",
			entry: {
				title: "T",
				username: "u",
				url: null,
				tags: [],
				group_id: null,
				url_match_mode: "auto",
			},
			url: "https://example.com/login",
			username: "u",
			password: "p",
		});
		expect(noId.error).toMatch(/entry_id/i);
		expect(captured).toBeNull();
	});
});
