import { describe, expect, it, beforeAll } from "vitest";

// v1.8.4 P2-2 behavioral harness for sendToApp's failure classification.
// connectionStatus is background-native.js MODULE state, unreachable from
// pure-function tests, so this file drives the real module with the same
// chrome-stub shape as background-save-prompt.test.js:
//   - a structured COMMAND_FAILED body ("Entry not found") rethrows
//     verbatim with the code attached and must NOT break the connection;
//   - a structured HOST_TRANSPORT_ERROR body disconnects with the friendly
//     copy;
//   - an UNstructured browser failure (chrome.runtime.lastError, no
//     response body) still disconnects through the connection-errors.js
//     phrase list, while an unstructured non-transport message rethrows.
const nmResponder = { impl: null };

globalThis.chrome = {
	runtime: {
		id: "test-runtime-id",
		lastError: null,
		onMessage: { addListener: () => {} },
		onInstalled: { addListener: () => {} },
		onStartup: { addListener: () => {} },
		sendNativeMessage: (host, msg, cb) => nmResponder.impl(msg, cb),
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

function failWith(message, code) {
	nmResponder.impl = (msg, cb) => {
		cb({
			id: msg.id,
			success: false,
			error_message: message,
			error_code: code,
		});
	};
}

// Rejects when sendToApp unexpectedly resolves; returns the error otherwise.
function captureFailure(promise) {
	return promise.then(
		() => {
			throw new Error("sendToApp should have failed");
		},
		(error) => error,
	);
}

let backgroundNative;

beforeAll(async () => {
	nmResponder.impl = (msg, cb) => {
		if (msg.command === "handshake") {
			cb({ id: 0, success: true, data: { protocol_version: 1 } });
			return;
		}
		if (msg.command === "pair") {
			cb({ id: 0, success: true, data: { token: "tok-123" } });
			return;
		}
		cb({ id: msg.id, success: false, error: "Unhandled command in test" });
	};
	backgroundNative = await import("./background-native.js");
	// Pair first so apiToken exists for authenticated commands.
	const result = await backgroundNative.startPairing();
	if (result !== "paired") {
		throw new Error("test harness pairing failed");
	}
});

describe("sendToApp error_code classification (v1.8.4 P2-2)", () => {
	it("a structured COMMAND_FAILED business error rethrows verbatim and keeps the connection", async () => {
		expect(backgroundNative.connectionStatus).toBe("connected");
		failWith("Entry not found", "COMMAND_FAILED");
		const error = await captureFailure(
			backgroundNative.sendToApp("get_entry_meta", { id_param: "e1" }),
		);
		expect(error.message).toBe("Entry not found");
		expect(error.code).toBe("COMMAND_FAILED");
		// The old bare-substring catch flipped the status to "disconnected"
		// for exactly this message — the popup would blame a stopped app.
		expect(backgroundNative.connectionStatus).toBe("connected");
	});

	it("a structured HOST_TRANSPORT_ERROR disconnects with the friendly copy", async () => {
		failWith("Native messaging host has exited", "HOST_TRANSPORT_ERROR");
		const error = await captureFailure(
			backgroundNative.sendToApp("is_vault_unlocked"),
		);
		expect(error.message).toContain("exited unexpectedly");
		expect(backgroundNative.connectionStatus).toBe("disconnected");
	});

	it("an unstructured browser transport failure disconnects via the phrase list", async () => {
		// No response body at all — the browser reports the failure through
		// runtime.lastError, so there is no error_code to classify by.
		globalThis.chrome.runtime.lastError = {
			message: "Specified native messaging host not found",
		};
		nmResponder.impl = (msg, cb) => cb(undefined);
		const error = await captureFailure(
			backgroundNative.sendToApp("is_vault_unlocked"),
		);
		expect(error.message).toContain("is not registered");
		expect(backgroundNative.connectionStatus).toBe("disconnected");
		globalThis.chrome.runtime.lastError = null;
	});

	it("an unstructured non-transport message rethrows and leaves the status alone", async () => {
		const before = backgroundNative.connectionStatus;
		globalThis.chrome.runtime.lastError = { message: "Some unrelated failure" };
		nmResponder.impl = (msg, cb) => cb(undefined);
		const error = await captureFailure(
			backgroundNative.sendToApp("is_vault_unlocked"),
		);
		expect(error.message).toBe("Some unrelated failure");
		expect(error.code).toBeUndefined();
		expect(backgroundNative.connectionStatus).toBe(before);
		globalThis.chrome.runtime.lastError = null;
	});
});
