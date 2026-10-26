import { useEffect, useMemo, useState } from "react";
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

	// Values start empty (edit) and fill when the secret channel runs; the
	// create form starts fully empty. Mirrors the parent's formData reset.
	useEffect(() => {
		setCustomFields(
			selectedEntry ? customFieldsFromMeta(selectedEntry.custom_fields) : [],
		);
		setOriginalCustomFields(null);
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
	// resolves null — the caller aborts the save.
	const fetchAndResolve = async (
		entry: EntrySummary,
		rows: CustomFieldRow[],
	): Promise<ResolvedCustomFields | null> => {
		try {
			setSecretLoading(true);
			const secret = await fetchSecret(entry.id);
			const loaded = secret.custom_fields ?? [];
			const filled = fillMissingValues(rows, loaded);
			setOriginalCustomFields(loaded);
			setCustomFields(filled);
			return { rows: filled, baseline: loaded };
		} catch {
			onFetchFailed();
			return null;
		} finally {
			setSecretLoading(false);
		}
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
				return fetchAndResolve(selectedEntry, rows);
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
		resolveForSave,
		patchFragment,
	};
}
