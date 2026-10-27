import { useEffect, useMemo, useRef, useState } from "react";
import {
	customFieldsFromMeta,
	fillMissingValues,
	filterEmptyRows,
	sameCustomFields,
	stripCustomFieldRowIds,
	type CustomFieldRow,
} from "../components/CustomFieldsEditor";
import type {
	CustomFieldInput,
	EntrySecretResponse,
	EntrySummary,
} from "../types";

interface UseCustomFieldsOptions {
	/** The entry being edited, or null on the create form. */
	selectedEntry: EntrySummary | null;
	/**
	 * Secret-channel fetch shared with the password reveal / notes load.
	 * Must reject on failure (including the empty-response guard) —
	 * resolveForSave treats a rejection as "abort the save" and reports it
	 * through onFetchFailed.
	 */
	fetchSecret: (id: string) => Promise<EntrySecretResponse>;
	/** Invoked when the guarded save-time fetch fails (owner surfaces it). */
	onFetchFailed: () => void;
	/** Loading signal shared with the owner's other secret-channel fetches. */
	setSecretLoading: (loading: boolean) => void;
}

/** Save-path resolution outcome (edit mode). */
interface ResolvedCustomFields {
	/**
	 * Effective current rows: blank rows dropped, values filled in. Rows
	 * still carry their UI-internal id here — patchFragment strips it at
	 * the IPC boundary.
	 */
	rows: CustomFieldRow[];
	/**
	 * Diff/comparison baseline: the loaded values when the secret channel
	 * ran, otherwise the meta-derived rows (labels + flags, empty values).
	 */
	baseline: CustomFieldInput[];
}

/**
 * Whole-replacement patch fragment for the pending update request:
 * `{ custom_fields: rows }` when the rows differ from the stored set, or an
 * empty record (omitted = the backend leaves them untouched).
 */
export type CustomFieldsPatchFragment =
	| { custom_fields: CustomFieldInput[] }
	| Record<string, never>;

export interface CustomFieldsController {
	customFields: CustomFieldRow[];
	setCustomFields: (rows: CustomFieldRow[]) => void;
	mergeLoadedCustomFields: (secret: EntrySecretResponse) => void;
	/** Create-form dirtiness: at least one row carries content. */
	hasContentRows: boolean;
	/** Edit-form dirtiness: rows differ from the stored set. */
	dirtyFromStored: boolean;
	/**
	 * Save-path resolution (edit mode). Resolves SYNCHRONOUSLY (plain value)
	 * when no guarded fetch is needed so the caller's confirmation modal
	 * opens in the same tick — the original inline behavior the save tests
	 * rely on. Returns a promise only when the guarded fetch runs.
	 */
	resolveForSave: () =>
		| ResolvedCustomFields
		| null
		| Promise<ResolvedCustomFields | null>;
	/**
	 * Whole-replacement patch fragment: carries the rows only when they
	 * differ from the stored set (omitted = the backend leaves them
	 * untouched). Spread into the pending update request.
	 */
	patchFragment: (
		baseline: CustomFieldInput[],
		rows: CustomFieldRow[],
	) => CustomFieldsPatchFragment;
	/**
	 * v1.6.1 F3: lazy-load the stored values on the user's first interaction
	 * with the Custom Fields area. `trigger` is "focus" (the container's
	 * onFocusCapture — Tab/click into any input) or "explicit" (a row's
	 * reveal-eye click). No-ops when there is nothing to load (create form,
	 * no stored fields, values already loaded). Runs the SAME guarded fetch
	 * as resolveForSave — one in-flight promise is shared, so focus-then-Save
	 * spends exactly one get_entry_secret round trip.
	 */
	loadValues: (trigger: "focus" | "explicit") => void;
}

/**
 * v1.6.0 custom-field controller (WP5 line-count reduction): the row state,
 * the secret-channel value loading, and the save assembly of EntryScreen,
 * extracted verbatim — this is pure plumbing relocation, not a behavior
 * change (WP2's test suites pin the semantics).
 *
 * Labels/secret flags come from the entry summary; VALUES are secret-channel
 * data — in edit mode they ride the existing get_entry_secret fetches
 * (password reveal / notes load), and the stored baseline stays null until
 * the first fetch (same posture as originalSecret).
 */
export function useCustomFields({
	selectedEntry,
	fetchSecret,
	onFetchFailed,
	setSecretLoading,
}: UseCustomFieldsOptions): CustomFieldsController {
	// Form rows carry the UI-internal id (CustomFieldRow) — it never leaves
	// this state except through the stripping boundaries below.
	const [customFields, setCustomFields] = useState<CustomFieldRow[]>([]);
	const [originalCustomFields, setOriginalCustomFields] = useState<
		CustomFieldInput[] | null
	>(null);
	// v1.6.1 F3: the single in-flight lazy-load/guard fetch, shared between
	// loadValues and resolveForSave so the round trip happens at most once.
	const inFlight = useRef<Promise<ResolvedCustomFields | null> | null>(null);
	// v1.6.1 F3: after a failed load, further FOCUS triggers back off until
	// the entry is re-entered — the explicit (eye) trigger and the save guard
	// are never suppressed.
	const suppressAutoLoad = useRef(false);
	// v1.6.1 P1: latest-rows mirror. The shared in-flight fetch outlives the
	// render that started it, so fetchAndResolve assembles its resolved rows
	// from here at RESOLUTION time — a snapshot captured at start would drop
	// rows typed/added during the flight from both the modal diff and the
	// committed patch (silent data loss).
	const rowsRef = useRef(customFields);
	rowsRef.current = customFields;

	// Values start empty (edit) and fill when the secret channel runs; the
	// create form starts fully empty. Mirrors the parent's formData reset.
	useEffect(() => {
		setCustomFields(
			selectedEntry ? customFieldsFromMeta(selectedEntry.custom_fields) : [],
		);
		setOriginalCustomFields(null);
		// Re-entering an entry clears the focus backoff and drops the share
		// reference to any in-flight fetch (the request itself is not
		// cancellable — same posture as the pre-existing secret fetches).
		suppressAutoLoad.current = false;
		inFlight.current = null;
	}, [selectedEntry]);

	// Every secret-channel response also carries the custom-field values, so
	// the existing fetches (password reveal, notes load) fill the rows in the
	// same round trip — no separate request. The first response becomes the
	// comparison base; values only fill untouched rows so user typing is
	// never clobbered by a later reveal.
	const mergeLoadedCustomFields = (secret: EntrySecretResponse) => {
		const loaded = secret.custom_fields ?? [];
		setOriginalCustomFields((prev) => prev ?? loaded);
		setCustomFields((prev) => fillMissingValues(prev, loaded));
	};

	// Stored baseline for the edit-form dirty check: the loaded values when
	// the secret channel has run, otherwise the meta-derived rows (labels,
	// empty values), so untouched rows stay clean until then. The meta-derived
	// rows are throwaway id-tagged rows — every consumer compares via
	// sameCustomFields, which reads only the (label, value, secret) triple.
	const storedRows = useMemo<CustomFieldInput[]>(
		() =>
			originalCustomFields ??
			customFieldsFromMeta(selectedEntry?.custom_fields),
		[originalCustomFields, selectedEntry],
	);
	const currentRows = useMemo(
		() => filterEmptyRows(customFields),
		[customFields],
	);

	const hasContentRows = currentRows.length > 0;
	const dirtyFromStored = !sameCustomFields(storedRows, currentRows);

	// The guarded-fetch branch of resolveForSave, isolated so the no-fetch
	// path can stay synchronous. Failure reports through onFetchFailed and
	// resolves null — the caller aborts the save. Takes no rows argument: the
	// resolved rows are assembled from rowsRef at RESOLUTION time (P1 — the
	// flight can outlive the render that started it).
	const fetchAndResolve = async (
		entry: EntrySummary,
	): Promise<ResolvedCustomFields | null> => {
		try {
			setSecretLoading(true);
			const secret = await fetchSecret(entry.id);
			const loaded = secret.custom_fields ?? [];
			// Latest rows win: fill values into what the form holds NOW, then
			// drop blanks — rows typed/added mid-flight are part of the result.
			const filled = filterEmptyRows(fillMissingValues(rowsRef.current, loaded));
			setOriginalCustomFields(loaded);
			// The form fills functionally (fillMissingValues never overwrites
			// typed values — same update as mergeLoadedCustomFields).
			setCustomFields((prev) => fillMissingValues(prev, loaded));
			return { rows: filled, baseline: loaded };
		} catch {
			onFetchFailed();
			return null;
		} finally {
			setSecretLoading(false);
		}
	};

	/**
	 * v1.6.1 F3: the lazy-load trigger. ANY failure sets the backoff flag
	 * (fetchAndResolve maps failures to null, never rejects); only the focus
	 * trigger CONSUMES it — explicit triggers and the save guard stay live.
	 */
	const loadValues = (trigger: "focus" | "explicit") => {
		if (!selectedEntry) return;
		if (originalCustomFields !== null) return;
		if (customFieldsFromMeta(selectedEntry.custom_fields).length === 0) return;
		if (trigger === "focus" && suppressAutoLoad.current) return;
		if (inFlight.current) return;
		inFlight.current = fetchAndResolve(selectedEntry)
			.then((resolved) => {
				if (resolved === null) {
					suppressAutoLoad.current = true;
				}
				return resolved;
			})
			.finally(() => {
				inFlight.current = null;
			});
	};

	const resolveForSave = ():
		| ResolvedCustomFields
		| null
		| Promise<ResolvedCustomFields | null> => {
		if (!selectedEntry) return null;

		// Whole-replacement semantics: composing the patch needs every stored
		// value. If the user edited rows before any secret fetch brought the
		// values in, run one guarded fetch now (same channel as the password
		// reveal) — without it the untouched value boxes are empty and would
		// WIPE the stored values on commit. An entry with NO stored fields
		// short-circuits past the fetch: there is nothing to protect, and the
		// fetch would only spend a round trip (its get_entry_secret
		// last_used_at bump side effect is accepted on the paths that do run
		// it — same semantics as the desktop reveal/copy; no Rust variant is
		// added for the save path).
		const rows = filterEmptyRows(customFields);
		if (originalCustomFields === null) {
			const metaRows = customFieldsFromMeta(selectedEntry.custom_fields);
			if (metaRows.length > 0 && !sameCustomFields(metaRows, rows)) {
				// v1.6.1 F3: a lazy load already in flight IS the guarded fetch —
				// return the same promise so focus-then-Save spends exactly one
				// get_entry_secret round trip (the busy-lock semantics of the
				// v1.6.0 tests are untouched: awaiting the shared promise still
				// holds the caller's re-entry lock).
				if (inFlight.current) return inFlight.current;
				const pending = fetchAndResolve(selectedEntry).finally(() => {
					inFlight.current = null;
				});
				inFlight.current = pending;
				return pending;
			}
		}
		// Diff/comparison baseline: the loaded values when the secret channel
		// ran, otherwise the meta-derived rows (labels + flags, empty values).
		// Comparing a never-fetched entry against "no stored fields" would
		// phantom-add every existing row and wipe them on commit.
		return {
			rows,
			baseline:
				originalCustomFields ??
				customFieldsFromMeta(selectedEntry.custom_fields),
		};
	};

	const patchFragment = (
		baseline: CustomFieldInput[],
		rows: CustomFieldRow[],
	): CustomFieldsPatchFragment =>
		sameCustomFields(baseline, rows)
			? {}
			// IPC boundary: the rows go out as the plain wire shape (the
			// UI-internal row id is stripped here).
			: { custom_fields: stripCustomFieldRowIds(rows) };

	return {
		customFields,
		setCustomFields,
		mergeLoadedCustomFields,
		hasContentRows,
		dirtyFromStored,
		loadValues,
		resolveForSave,
		patchFragment,
	};
}
