/** Convert Error, Tauri string rejections, and serialized Rust error enums to text. */
import type { VaultError } from "../types";

/**
 * M10: type guard for the serialized Rust `VaultError` enum (serde external
 * tagging — unit variants arrive as strings, payload variants as single-key
 * objects). Mirrors src/types/index.ts `VaultError`, which is regenerated
 * from src-tauri/crates/application/src/error.rs.
 */
export function isVaultError(error: unknown): error is VaultError {
	if (typeof error === "string") {
		return VAULT_ERROR_UNIT_VARIANTS.has(error);
	}
	if (error !== null && typeof error === "object" && !Array.isArray(error)) {
		const keys = Object.keys(error);
		return keys.length === 1 && VAULT_ERROR_PAYLOAD_VARIANTS.has(keys[0]);
	}
	return false;
}

const VAULT_ERROR_UNIT_VARIANTS: ReadonlySet<string> = new Set([
	"VaultLocked",
	"VaultAlreadyExists",
	"LegacyVaultRequiresMigration",
	"InvalidPassword",
	"EntryNotFound",
	"WeakKdfParams",
	"BiometricUnavailable",
	"BiometricCancelled",
	"BiometricLockedOut",
	"WrapBlobCorrupt",
	"RecoveryKeyInvalid",
	"RecoveryNotEnabled",
	"CurrentPasswordInvalid",
	"IntegrityCheckFailed",
]);

const VAULT_ERROR_PAYLOAD_VARIANTS: ReadonlySet<string> = new Set([
	"EncryptionFailed",
	"DecryptionFailed",
	"DatabaseError",
	"InternalError",
	"InvalidBackup",
	"KeychainError",
	"InvalidInput",
	"RateLimited",
]);

export function errorMessage(error: unknown, fallback: string): string {
	// RateLimited carries its payload in a numeric field that nestedMessage
	// cannot render; surface the retry window directly (M10). Every other
	// VaultError keeps falling through to the existing extraction logic.
	if (
		error !== null &&
		typeof error === "object" &&
		"RateLimited" in error &&
		typeof (error as { RateLimited: unknown }).RateLimited === "object" &&
		(error as { RateLimited: { retry_after_secs?: unknown } }).RateLimited
			.retry_after_secs !== undefined
	) {
		const secs = (error as { RateLimited: { retry_after_secs: number } })
			.RateLimited.retry_after_secs;
		return `Too many attempts — retry in ${secs}s`;
	}
	return nestedMessage(error, 0) ?? fallback;
}

function nestedMessage(value: unknown, depth: number): string | undefined {
	if (depth > 4) return undefined;
	if (value instanceof Error && value.message.trim()) return value.message;
	if (typeof value === "string" && value.trim()) return value;
	if (!value || typeof value !== "object") return undefined;

	const record = value as Record<string, unknown>;
	for (const key of ["message", "error_message", "error"]) {
		const message = nestedMessage(record[key], depth + 1);
		if (message) return message;
	}
	for (const nested of Object.values(record)) {
		const message = nestedMessage(nested, depth + 1);
		if (message) return message;
	}
	return undefined;
}
