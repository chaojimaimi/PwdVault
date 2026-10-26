import { useState, type KeyboardEvent } from "react";
import { EyeIcon, EyeOffIcon, LockIcon } from "./Icons";
import type { ChangeItem } from "./ConfirmationModal";
import type {
	CustomFieldInput,
	CustomFieldMeta,
	CustomFieldValue,
} from "../types";

/**
 * A form row: the wire shape plus a UI-internal row identity. `id` is the
 * stable React key (assigned once when a row enters the form state, copied
 * through every value-fill/merge) — keying by object identity broke the
 * moment an update created a new row object per keystroke (focus was lost
 * on every character). It must never leave the UI: every IPC boundary and
 * every comparison strips/ignores it.
 */
export type CustomFieldRow = CustomFieldInput & { id: number };

// Module-level allocator: ids only need uniqueness within one mounted list,
// and a plain counter keeps customFieldsFromMeta/addRow allocation-free of
// component state. Never serialized anywhere.
let rowIdSeq = 0;
const nextRowId = (): number => {
	rowIdSeq += 1;
	return rowIdSeq;
};

/** Output-boundary strip: rows go back to the plain wire shape. */
export function stripCustomFieldRowIds(
	rows: CustomFieldRow[],
): CustomFieldInput[] {
	return rows.map(({ label, value, secret }) => ({ label, value, secret }));
}

interface CustomFieldsEditorProps {
	/** Current row list; the parent owns it (it feeds the save patch). */
	value: CustomFieldRow[];
	onChange: (fields: CustomFieldRow[]) => void;
}

/** Labels are compared/committed trimmed; values are compared verbatim. */
export function normalizeCustomLabel(label: string): string {
	return label.trim();
}

/**
 * v1.6.0: order-insensitive custom-field equality. Rows pair up by their
 * trimmed label and compare as full (label, value, secret) triples;
 * reordering rows is not a change. Sort-then-join, deliberately not a Set —
 * duplicate multiplicity must survive (sameTags precedent). The value is
 * compared verbatim (never trimmed — values may be meaningful secrets).
 * Exported for the pure-function test matrix (sameTags precedent). Lives
 * beside the other pure helpers; moved verbatim out of EntryScreen in the
 * WP5 line-count reduction.
 */
export function sameCustomFields(
	a: CustomFieldInput[],
	b: CustomFieldInput[],
): boolean {
	if (a.length !== b.length) return false;
	const canonical = (rows: CustomFieldInput[]) =>
		rows
			.map(
				(f) =>
					`${normalizeCustomLabel(f.label)}\u0000${f.value}\u0000${f.secret}`,
			)
			.sort()
			.join("\u0001");
	return canonical(a) === canonical(b);
}

/**
 * Drops rows that carry no data at all (empty label AND empty value) —
 * the backend rejects an empty label, so only fully-blank rows may be
 * silently discarded; a value without a label stays and fails validation
 * server-side (documented behaviour). Generic: it preserves the exact row
 * type, so id-tagged editor rows keep their identity through the filter.
 */
export function filterEmptyRows<T extends CustomFieldInput>(
	rows: T[],
): T[] {
	return rows.filter(
		(f) => normalizeCustomLabel(f.label) !== "" || f.value !== "",
	);
}

/**
 * Edit-mode starting rows from the summary metadata: labels and masking
 * flags are public, values are secret-channel data and start empty until
 * a get_entry_secret fetch fills them in. Each row is allocated a fresh
 * UI-internal id (the stable React key).
 */
export function customFieldsFromMeta(
	meta: CustomFieldMeta[] | undefined,
): CustomFieldRow[] {
	return (meta ?? []).map((f) => ({
		id: nextRowId(),
		label: f.label,
		value: "",
		secret: f.secret,
	}));
}

/**
 * Fills values from a secret-channel response into rows the user has not
 * touched (empty value + matching trimmed label). Rows keep their object
 * identity (and any UI-internal id) unless filled — the editor keys rows by
 * that id, so untouched inputs never remount. User-typed values always win
 * over loaded ones.
 */
export function fillMissingValues<T extends CustomFieldInput>(
	rows: T[],
	loaded: CustomFieldValue[],
): T[] {
	const byLabel = new Map(
		loaded.map((f) => [normalizeCustomLabel(f.label), f.value]),
	);
	return rows.map((f) => {
		const value = byLabel.get(normalizeCustomLabel(f.label));
		if (f.value !== "" || value === undefined) return f;
		return { ...f, value };
	});
}

/**
 * The confirmation-modal diff rows for custom fields. Both sides are
 * pre-filtered (filterEmptyRows) and differ (the caller gates on
 * sameCustomFields). Rows pair by trimmed label, so reordering produces
 * no diff; leftovers become added (oldValue "") or removed (newValue "")
 * rows. Secret rows reuse the modal's •••• password branch — it masks
 * both sides, which also keeps removed secret values from leaking into
 * the confirmation list.
 */
export function buildCustomFieldChanges(
	original: CustomFieldInput[],
	current: CustomFieldInput[],
): ChangeItem[] {
	const groups = new Map<
		string,
		{ original: CustomFieldInput[]; current: CustomFieldInput[] }
	>();
	const groupOf = (label: string) => {
		const key = normalizeCustomLabel(label);
		let group = groups.get(key);
		if (!group) {
			group = { original: [], current: [] };
			groups.set(key, group);
		}
		return group;
	};
	original.forEach((f) => groupOf(f.label).original.push(f));
	current.forEach((f) => groupOf(f.label).current.push(f));

	const changes: ChangeItem[] = [];
	for (const label of [...groups.keys()].sort()) {
		const pair = groups.get(label)!;
		const count = Math.max(pair.original.length, pair.current.length);
		for (let i = 0; i < count; i += 1) {
			const before = pair.original[i];
			const after = pair.current[i];
			// Duplicate labels are rejected by the backend validation; the
			// index suffix only exists so the modal's React key stays unique
			// if a duplicate ever reaches this diff.
			const fieldId = count > 1 ? `custom:${label}:${i}` : `custom:${label}`;
			if (!before) {
				changes.push({
					fieldId,
					label,
					oldValue: "",
					newValue: after.value,
					valueType: after.secret ? "password" : "text",
				});
			} else if (!after) {
				changes.push({
					fieldId,
					label,
					oldValue: before.value,
					newValue: "",
					valueType: before.secret ? "password" : "text",
				});
			} else if (
				before.value !== after.value ||
				before.secret !== after.secret
			) {
				changes.push({
					fieldId,
					label,
					oldValue: before.value,
					newValue: after.value,
					valueType: after.secret ? "password" : "text",
				});
			}
		}
	}
	return changes;
}

/**
 * detectChanges' custom-field branch (v1.6.0), extracted so the whole diff
 * logic lives beside its helpers (WP5 line-count reduction). Custom fields
 * are whole-replacement metadata: rows pair by the trimmed label (reorder
 * is not a change); a real difference emits added/removed/modified diff
 * rows, secret rows masked like the password row. Values reach the diff
 * only via the secret channel (see EntryScreen handleSave). `original` is
 * the effective baseline — loaded values when the secret channel ran,
 * meta-derived rows otherwise; null reads as "no stored fields". `current`
 * is the raw form list (blank rows are dropped here).
 */
export function appendCustomFieldChanges(
	changes: ChangeItem[],
	original: CustomFieldInput[] | null,
	current: CustomFieldInput[],
): ChangeItem[] {
	const baseline = original ?? [];
	const rows = filterEmptyRows(current);
	if (sameCustomFields(baseline, rows)) return changes;
	return [...changes, ...buildCustomFieldChanges(baseline, rows)];
}

/**
 * Custom-field rows editor (v1.6.0). Fully controlled like TagsEditor: the
 * parent owns the array, this component holds only per-row reveal state.
 * Row React keys come from the row's own `id` (CustomFieldRow) — positional
 * keys would shuffle input state when a row is deleted, and keying by
 * object identity lost focus on every keystroke once updates became new
 * objects. RENAME SEMANTICS: renaming a label is, for the stored set, a
 * delete-old-row + add-new-row (the whole-replacement commit pairs values
 * by trimmed label, so the original value does NOT migrate to the renamed
 * row) — the confirmation modal shows exactly that as one removed + one
 * added row. The lock button is the per-row SECRET switch ("stored as
 * sensitive", masked by default); the eye button is the per-row REVEAL
 * toggle — two independent controls. Rows live inside the entry form, so
 * Enter is always prevented (implicit submission would save the entry —
 * TagsEditor precedent).
 */
export function CustomFieldsEditor({
	value,
	onChange,
}: CustomFieldsEditorProps) {
	const [revealed, setRevealed] = useState<Set<number>>(new Set());

	const updateRow = (index: number, next: CustomFieldRow) => {
		onChange(value.map((row, i) => (i === index ? next : row)));
	};

	const removeRow = (index: number) => {
		onChange(value.filter((_, i) => i !== index));
	};

	const addRow = () => {
		onChange([
			...value,
			{ id: nextRowId(), label: "", value: "", secret: false },
		]);
	};

	const toggleRevealed = (id: number) => {
		setRevealed((prev) => {
			const next = new Set(prev);
			if (next.has(id)) {
				next.delete(id);
			} else {
				next.add(id);
			}
			return next;
		});
	};

	// Rows are inputs inside the entry form: an unprevented Enter would run
	// the form's implicit submission (saving the entry) mid-edit.
	const swallowEnter = (e: KeyboardEvent<HTMLInputElement>) => {
		if (e.key === "Enter") e.preventDefault();
	};

	return (
		<>
			<span className="form-label">Custom Fields</span>
			{value.map((row, index) => {
				const isRevealed = revealed.has(row.id) || !row.secret;
				return (
					<div className="tag-input-row" key={row.id}>
						<input
							type="text"
							className="form-input"
							value={row.label}
							onChange={(e) =>
								updateRow(index, { ...row, label: e.target.value })
							}
							onKeyDown={swallowEnter}
							placeholder="Name"
							aria-label={`Field ${index + 1} label`}
						/>
						<input
							type={isRevealed ? "text" : "password"}
							className="form-input"
							value={row.value}
							onChange={(e) =>
								updateRow(index, { ...row, value: e.target.value })
							}
							onKeyDown={swallowEnter}
							placeholder={isRevealed ? "Value" : "Value (hidden)"}
							autoComplete="off"
							aria-label={`Field ${index + 1} value`}
						/>
						<button
							className="btn btn-secondary btn-inline"
							type="button"
							onClick={() => updateRow(index, { ...row, secret: !row.secret })}
							aria-label={
								row.secret
									? `Mark field ${index + 1} as plain text`
									: `Mark field ${index + 1} as secret`
							}
							aria-pressed={row.secret}
						>
							<LockIcon />
						</button>
						{row.secret && (
							<button
								className="btn btn-secondary btn-inline"
								type="button"
								onClick={() => toggleRevealed(row.id)}
								aria-label={
									isRevealed
										? `Hide field ${index + 1} value`
										: `Show field ${index + 1} value`
								}
								aria-pressed={isRevealed}
							>
								{isRevealed ? <EyeOffIcon /> : <EyeIcon />}
							</button>
						)}
						<button
							className="btn btn-secondary btn-inline"
							type="button"
							onClick={() => removeRow(index)}
							aria-label={`Remove field ${index + 1}`}
						>
							×
						</button>
					</div>
				);
			})}
			<div className="tag-input-row">
				<button
					className="btn btn-secondary btn-inline"
					type="button"
					onClick={addRow}
				>
					Add field
				</button>
			</div>
		</>
	);
}
