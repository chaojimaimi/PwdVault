import { fireEvent, render, screen } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import {
	buildCustomFieldChanges,
	CustomFieldsEditor,
	customFieldsFromMeta,
	fillMissingValues,
	filterEmptyRows,
	type CustomFieldRow,
} from "./CustomFieldsEditor";
import type { CustomFieldInput } from "../types";

/** Wire-shape row for the pure helpers (no UI-internal id). */
const field = (
	label: string,
	value: string,
	secret = false,
): CustomFieldInput => ({ label, value, secret });

/**
 * Editor row with the UI-internal id. `id` defaults to 1 for single-row
 * renders so emitted updates ({...row, field}) round-trip toEqual cleanly;
 * multi-row lists pass explicit distinct ids.
 */
const row = (
	label: string,
	value: string,
	secret = false,
	id = 1,
): CustomFieldRow => ({ id, label, value, secret });

test("renders rows with labelled inputs and reports edits through onChange", () => {
	const onChange = vi.fn();
	render(
		<CustomFieldsEditor value={[row("api_key", "s3cret", true)]} onChange={onChange} />,
	);

	const labelInput = screen.getByLabelText("Field 1 label");
	expect(labelInput).toHaveValue("api_key");
	const valueInput = screen.getByLabelText("Field 1 value");
	// secret rows are masked by default
	expect(valueInput).toHaveAttribute("type", "password");

	fireEvent.change(labelInput, { target: { value: "api key" } });
	expect(onChange).toHaveBeenLastCalledWith([row("api key", "s3cret", true)]);

	fireEvent.change(valueInput, { target: { value: "v2" } });
	expect(onChange).toHaveBeenLastCalledWith([row("api_key", "v2", true)]);
});

test("Add field appends a blank id-tagged row; Remove deletes the named row", () => {
	const onChange = vi.fn();
	render(
		<CustomFieldsEditor
			// High explicit ids so the freshly allocated id cannot collide
			// with them (the module counter starts low).
			value={[row("a", "1", false, 101), row("b", "2", false, 102)]}
			onChange={onChange}
		/>,
	);

	fireEvent.click(screen.getByRole("button", { name: "Add field" }));
	const emitted = onChange.mock.lastCall?.[0] as CustomFieldRow[];
	expect(emitted.slice(0, 2)).toEqual([
		row("a", "1", false, 101),
		row("b", "2", false, 102),
	]);
	// The appended blank row carries a fresh unique UI-internal id (its
	// stable React key) — asserted by shape, not by counter value.
	expect(emitted[2]).toMatchObject({ label: "", value: "", secret: false });
	expect(new Set(emitted.map((r) => r.id)).size).toBe(3);

	fireEvent.click(screen.getByRole("button", { name: "Remove field 1" }));
	expect(onChange).toHaveBeenLastCalledWith([row("b", "2", false, 102)]);
});

test("deleting a middle row keeps the sibling inputs' values in place", () => {
	// Regression pin for the positional-key hazard: keys are row-id-stable,
	// so removing row 1 must not shuffle row 2's value into row 1's inputs.
	const onChange = vi.fn();
	const { rerender } = render(
		<CustomFieldsEditor
			value={[row("a", "1", false, 1), row("b", "2", false, 2), row("c", "3", false, 3)]}
			onChange={onChange}
		/>,
	);

	fireEvent.click(screen.getByRole("button", { name: "Remove field 2" }));
	rerender(
		<CustomFieldsEditor
			value={[row("a", "1", false, 1), row("c", "3", false, 3)]}
			onChange={onChange}
		/>,
	);

	expect(screen.getByLabelText("Field 1 label")).toHaveValue("a");
	expect(screen.getByLabelText("Field 1 value")).toHaveValue("1");
	expect(screen.getByLabelText("Field 2 label")).toHaveValue("c");
	expect(screen.getByLabelText("Field 2 value")).toHaveValue("3");
});

test("typing keeps focus in the same input across the parent rerender", () => {
	// The P1 regression pin: keys come from the row's own id, so an edit
	// (the parent swaps in a NEW row object with the SAME id) must not
	// remount the input. The previous object-identity WeakMap keys gave the
	// edited row a fresh key every keystroke — React replaced the DOM node
	// and focus was lost on the first character. Under jsdom a remount
	// detaches the old node, so document.activeElement stops being it.
	const onChange = vi.fn((next: CustomFieldRow[]) => {
		current = next;
	});
	let current: CustomFieldRow[] = [row("", "", false)];
	const { rerender } = render(
		<CustomFieldsEditor value={current} onChange={onChange} />,
	);

	const labelInput = screen.getByLabelText("Field 1 label");
	labelInput.focus();
	expect(document.activeElement).toBe(labelInput);

	fireEvent.change(labelInput, { target: { value: "a" } });
	// The controlled flow: rerender with exactly what onChange emitted.
	rerender(<CustomFieldsEditor value={current} onChange={onChange} />);
	expect(document.activeElement).toBe(labelInput);
});

test("character-by-character typing never drops focus", () => {
	// Same pin, exercised the way a real user types: one change + parent
	// rerender per character, focus asserted after every round trip.
	const onChange = vi.fn((next: CustomFieldRow[]) => {
		current = next;
	});
	let current: CustomFieldRow[] = [row("", "", false)];
	const { rerender } = render(
		<CustomFieldsEditor value={current} onChange={onChange} />,
	);

	const valueInput = screen.getByLabelText("Field 1 value");
	valueInput.focus();
	let typed = "";
	for (const ch of ["s", "e", "c", "r", "e", "t"]) {
		typed += ch;
		fireEvent.change(valueInput, { target: { value: typed } });
		rerender(<CustomFieldsEditor value={current} onChange={onChange} />);
		expect(document.activeElement).toBe(valueInput);
	}
	expect(valueInput).toHaveValue("secret");
});

test("the lock toggle flips a plain row to secret through onChange", () => {
	const onChange = vi.fn();
	render(
		<CustomFieldsEditor value={[row("region", "us", false)]} onChange={onChange} />,
	);
	// The lock button exists on plain rows too — a row can be CREATED as
	// secret from the editor (the desktop previously had no such path).
	const lock = screen.getByRole("button", { name: "Mark field 1 as secret" });
	expect(lock).toHaveAttribute("aria-pressed", "false");
	// The reveal (eye) button belongs to secret rows only — the secret
	// switch and the reveal toggle stay two independent controls.
	expect(
		screen.queryByRole("button", { name: /field 1 value/ }),
	).not.toBeInTheDocument();

	fireEvent.click(lock);
	expect(onChange).toHaveBeenLastCalledWith([row("region", "us", true)]);
});

test("flipping back renders the row unmasked and reports secret=false", () => {
	const onChange = vi.fn((next: CustomFieldRow[]) => {
		current = next;
	});
	let current: CustomFieldRow[] = [row("api_key", "s3cret", true)];
	const { rerender } = render(
		<CustomFieldsEditor value={current} onChange={onChange} />,
	);

	fireEvent.click(
		screen.getByRole("button", { name: "Mark field 1 as plain text" }),
	);
	expect(onChange).toHaveBeenLastCalledWith([row("api_key", "s3cret", false)]);
	// Controlled flow: the parent rerenders with the flipped row.
	rerender(<CustomFieldsEditor value={current} onChange={onChange} />);
	// With the flag off the value renders as plain text and the eye toggle
	// disappears with it.
	expect(screen.getByLabelText("Field 1 value")).toHaveAttribute("type", "text");
	expect(
		screen.queryByRole("button", { name: /field 1 value/ }),
	).not.toBeInTheDocument();
});

test("secret rows toggle their mask through the aria-pressed button", () => {
	render(
		<CustomFieldsEditor value={[row("api_key", "s3cret", true)]} onChange={() => {}} />,
	);

	const toggle = screen.getByRole("button", { name: "Show field 1 value" });
	expect(toggle).toHaveAttribute("aria-pressed", "false");
	expect(screen.getByLabelText("Field 1 value")).toHaveAttribute(
		"type",
		"password",
	);

	fireEvent.click(toggle);
	expect(screen.getByRole("button", { name: "Hide field 1 value" })).toHaveAttribute(
		"aria-pressed",
		"true",
	);
	expect(screen.getByLabelText("Field 1 value")).toHaveAttribute("type", "text");
});

test("non-secret rows render as plain text with no mask toggle", () => {
	render(<CustomFieldsEditor value={[row("region", "us", false)]} onChange={() => {}} />);

	expect(screen.getByLabelText("Field 1 value")).toHaveAttribute("type", "text");
	expect(
		screen.queryByRole("button", { name: /field 1 value/ }),
	).not.toBeInTheDocument();
	expect(screen.getByRole("button", { name: "Remove field 1" })).toBeInTheDocument();
});

test("Enter in row inputs is swallowed (no form implicit submission)", () => {
	render(
		<CustomFieldsEditor value={[row("a", "1", true)]} onChange={() => {}} />,
	);

	// fireEvent resolves to false when preventDefault was called.
	expect(
		fireEvent.keyDown(screen.getByLabelText("Field 1 label"), { key: "Enter" }),
	).toBe(false);
	expect(
		fireEvent.keyDown(screen.getByLabelText("Field 1 value"), { key: "Enter" }),
	).toBe(false);
});

test("filterEmptyRows drops only fully blank rows", () => {
	expect(filterEmptyRows([field("", ""), field("  ", "")])).toEqual([]);
	expect(filterEmptyRows([field("a", "")])).toEqual([field("a", "")]);
	// A value without a label survives — the backend owns that rejection.
	expect(filterEmptyRows([field("", "v")])).toEqual([field("", "v")]);
});

test("customFieldsFromMeta maps summary metadata to fresh id-tagged rows", () => {
	expect(customFieldsFromMeta(undefined)).toEqual([]);
	const rows = customFieldsFromMeta([
		{ label: "api_key", secret: true },
		{ label: "region", secret: false },
	]);
	// Values stay empty (secret-channel data); each row gets a unique
	// UI-internal id — the stable React key.
	expect(
		rows.map(({ label, value, secret }) => ({ label, value, secret })),
	).toEqual([
		{ label: "api_key", value: "", secret: true },
		{ label: "region", value: "", secret: false },
	]);
	expect(new Set(rows.map((r) => r.id)).size).toBe(rows.length);
});

test("fillMissingValues fills untouched rows only; typed values win", () => {
	const loaded = [
		{ label: "api_key", value: "s3cret", secret: true },
		{ label: "region", value: "us", secret: false },
	];
	// Label matching trims; rows keep identity unless filled.
	const staged = [field(" api_key ", ""), field("typed", "mine"), field("region", "")];
	expect(fillMissingValues(staged, loaded)).toEqual([
		// Only the value is filled — the staged row's own flags stay.
		field(" api_key ", "s3cret"),
		field("typed", "mine"),
		field("region", "us"),
	]);
	// A user-typed value is never clobbered by the loaded one.
	expect(fillMissingValues([field("api_key", "mine")], loaded)).toEqual([
		field("api_key", "mine"),
	]);
	// Row identity rides along: id-tagged rows keep their id when filled.
	const withIds = [row("api_key", "", true, 11), row("typed", "mine", false, 12)];
	expect(fillMissingValues(withIds, loaded)).toEqual([
		row("api_key", "s3cret", true, 11),
		row("typed", "mine", false, 12),
	]);
});

test("buildCustomFieldChanges: added, removed, and modified rows", () => {
	expect(buildCustomFieldChanges([], [field("token", "t0k3n")])).toEqual([
		{
			fieldId: "custom:token",
			label: "token",
			oldValue: "",
			newValue: "t0k3n",
			valueType: "text",
		},
	]);
	expect(buildCustomFieldChanges([field("token", "t0k3n")], [])).toEqual([
		{
			fieldId: "custom:token",
			label: "token",
			oldValue: "t0k3n",
			newValue: "",
			valueType: "text",
		},
	]);
	expect(
		buildCustomFieldChanges([field("region", "us")], [field("region", "eu")]),
	).toEqual([
		{
			fieldId: "custom:region",
			label: "region",
			oldValue: "us",
			newValue: "eu",
			valueType: "text",
		},
	]);
});

test("buildCustomFieldChanges: secret rows reuse the password mask type", () => {
	expect(
		buildCustomFieldChanges([], [field("api_key", "s3cret", true)])[0].valueType,
	).toBe("password");
	expect(
		buildCustomFieldChanges([field("api_key", "s3cret", true)], [])[0].valueType,
	).toBe("password");
	// A secret-flag flip alone is a modified row (masked on the modal side).
	expect(
		buildCustomFieldChanges([field("v", "x", true)], [field("v", "x", false)]),
	).toEqual([
		{
			fieldId: "custom:v",
			label: "v",
			oldValue: "x",
			newValue: "x",
			valueType: "text",
		},
	]);
});

test("buildCustomFieldChanges: reorder and no-op produce no diff rows", () => {
	expect(
		buildCustomFieldChanges([field("a", "1"), field("b", "2")], [
			field("b", "2"),
			field("a", "1"),
		]),
	).toEqual([]);
	expect(buildCustomFieldChanges([field("a", "1")], [field("a", "1")])).toEqual([]);
});

test("buildCustomFieldChanges: duplicate labels get an index-suffixed fieldId", () => {
	// Both pairs in the duplicated group differ → both rows carry the
	// :index suffix so the modal's React keys stay unique.
	const changes = buildCustomFieldChanges(
		[field("x", "1"), field("x", "2")],
		[field("x", "9"), field("x", "8")],
	);
	expect(changes.map((c) => c.fieldId)).toEqual(["custom:x:0", "custom:x:1"]);
	expect(changes[0]).toMatchObject({ oldValue: "1", newValue: "9" });
	// A duplicate-label pair that does NOT change emits nothing (the suffix
	// never fabricates a diff row).
	expect(
		buildCustomFieldChanges([field("x", "1"), field("x", "2")], [
			field("x", "9"),
			field("x", "2"),
		]).map((c) => c.fieldId),
	).toEqual(["custom:x:0"]);
});
