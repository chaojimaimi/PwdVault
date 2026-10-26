import type { UrlMatchMode } from "../types";

/**
 * v1.5.0 WP4: the URL match override as a normalizable accessor — a summary
 * from a pre-v1.5.0 desktop (or any absent value) reads as "auto", matching
 * the Rust serde default and the extension's fallback. Unknown strings (the
 * TS type is an IPC trust boundary, not a runtime guarantee) degrade to
 * "auto" too, same as the extension's `|| "auto"`.
 * (WP5 line-count reduction: moved verbatim out of EntryScreen.)
 */
export function normalizeMatchMode(
	mode: UrlMatchMode | undefined,
): UrlMatchMode {
	return mode === "exact" || mode === "domain" ? mode : "auto";
}

/** Select options + confirmation-modal display values (single source). */
export const URL_MATCH_MODE_OPTIONS: {
	value: UrlMatchMode;
	label: string;
	hint: string;
}[] = [
	{
		value: "auto",
		label: "Auto (recommended)",
		hint: "Fills on the site's registrable domain — subdomains of the stored URL's site are allowed.",
	},
	{
		value: "exact",
		label: "Exact host",
		hint: "Fills only on exactly this host (subdomains and www variants do not match).",
	},
	{
		value: "domain",
		label: "Registrable domain",
		hint: "Always matches by registrable domain (eTLD+1), pinned even if Auto matching evolves.",
	},
];
