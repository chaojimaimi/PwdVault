import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// v1.8.1 cross-boundary contract guard: the dismissed-Touch-ID error string
// lives in BOTH the Rust wire shape (error.rs public_message) and the
// frontend silence guard (AuthContext.isBiometricCancelled). A unilateral
// copy change on either side must turn this test red — the v1.3.2 wire-shape
// migration silently broke the old guard for exactly this reason. File-anchored
// paths per the corpus-sync.test.js precedent (never CWD-relative).

const here = dirname(fileURLToPath(import.meta.url));
const RUST_ERROR_RS = join(
	here,
	"..",
	"..",
	"src-tauri",
	"crates",
	"application",
	"src",
	"error.rs",
);
const AUTH_CONTEXT_TSX = join(here, "AuthContext.tsx");
const CANCELLED_MESSAGE = "Touch ID was cancelled";

describe("biometric-cancelled cross-boundary contract", () => {
	it("pins the cancelled wire string on both sides (Rust wire shape ↔ frontend guard)", () => {
		expect(readFileSync(RUST_ERROR_RS, "utf8")).toContain(
			`VaultError::BiometricCancelled => "${CANCELLED_MESSAGE}"`,
		);
		// The trailing-comma+quote form anchors the SET MEMBER specifically —
		// a bare CANCELLED_MESSAGE check would also match this file's own
		// explanatory comments and stay green if the member were deleted
		// (react-review P3, mutation-tested).
		expect(readFileSync(AUTH_CONTEXT_TSX, "utf8")).toContain(
			`"${CANCELLED_MESSAGE}",`,
		);
	});
});
