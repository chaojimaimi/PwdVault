/** Convert Error, Tauri string rejections, and serialized Rust error enums to text. */
export function errorMessage(error: unknown, fallback: string): string {
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
