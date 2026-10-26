import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, test, vi } from "vitest";
import { detectChanges, EntryScreen } from "../EntryScreen";
import { sameCustomFields } from "../../components/CustomFieldsEditor";
import type {
	CreateEntryRequest,
	CustomFieldInput,
	EntrySummary,
} from "../../types";

// v1.6.0 WP2: custom fields — the editor wiring, the whole-replacement
// save semantics, and the secret-channel value loading. Contract under
// test:
//   1. sameCustomFields is a label-multiset triple comparison (reorder is
//      not a change);
//   2. detectChanges emits added/removed/modified custom rows with
//      custom:<label> ids, secret rows masked;
//   3. a metadata-only save never fetches secrets and OMITS custom_fields
//      (an empty-box wipe is the P0 hazard this suite pins shut);
//   4. editing rows before any secret fetch runs one guarded fetch at
//      save, so the replacement carries the real stored values.

const getEntrySecret = vi.fn();
const updateEntry = vi.fn().mockResolvedValue({});
const createEntry = vi.fn();
const deleteEntry = vi.fn();
const navigate = vi.fn();
const selectEntry = vi.fn();

const vaultState: { selectedEntry: EntrySummary | null } = {
	selectedEntry: null,
};
const vaultActions = {
	getEntrySecret,
	updateEntry,
	createEntry,
	deleteEntry,
	selectEntry,
};
const authActions = { navigate };

vi.mock("../../context/AppContext", () => ({
	useAuth: () => ({ actions: authActions }),
	useVault: () => ({ state: vaultState, actions: vaultActions }),
	useSettings: () => ({ state: { settings: {} }, actions: {} }),
}));
vi.mock("../../components/GroupSelector", () => ({
	default: () => <div data-testid="group-selector" />,
}));

beforeEach(() => {
	vi.clearAllMocks();
	updateEntry.mockResolvedValue({});
	vaultState.selectedEntry = null;
});

const row = (
	label: string,
	value: string,
	secret = false,
): CustomFieldInput => ({ label, value, secret });

function baseMeta(overrides: Partial<EntrySummary> = {}): EntrySummary {
	return {
		id: "entry-1",
		title: "Before",
		username: "user",
		url: "",
		tags: [],
		group_id: null,
		created_at: 1,
		updated_at: 1,
		...overrides,
	};
}

function form(overrides: Partial<CreateEntryRequest> = {}): CreateEntryRequest {
	return {
		title: "Before",
		url: "",
		username: "user",
		password: "",
		notes: "",
		tags: [],
		group_id: null,
		url_match_mode: "auto",
		...overrides,
	};
}

function fillRequiredFields() {
	fireEvent.change(screen.getByLabelText("Title *"), {
		target: { value: "Example" },
	});
	fireEvent.change(screen.getByLabelText("Username *"), {
		target: { value: "user@example.com" },
	});
	fireEvent.change(screen.getByLabelText("Password *"), {
		target: { value: "secret-password-1" },
	});
}

async function saveAndCapturePatch() {
	fireEvent.click(screen.getByRole("button", { name: "Save" }));
	fireEvent.click(await screen.findByText("I've reviewed these changes"));
	fireEvent.click(screen.getByRole("button", { name: "Save Changes" }));
	await waitFor(() => expect(updateEntry).toHaveBeenCalledOnce());
	return updateEntry.mock.calls[0][1];
}

describe("sameCustomFields", () => {
	test("identical, reordered, and empty sets are equal", () => {
		expect(sameCustomFields([], [])).toBe(true);
		expect(sameCustomFields([row("a", "1", true)], [row("a", "1", true)])).toBe(
			true,
		);
		expect(
			sameCustomFields(
				[row("a", "1"), row("b", "2", true)],
				[row("b", "2", true), row("a", "1")],
			),
		).toBe(true);
	});

	test("add, remove, value change, and secret flip are changes", () => {
		expect(sameCustomFields([], [row("a", "1")])).toBe(false);
		expect(sameCustomFields([row("a", "1")], [])).toBe(false);
		expect(sameCustomFields([row("a", "1")], [row("a", "2")])).toBe(false);
		expect(sameCustomFields([row("a", "1")], [row("a", "1", true)])).toBe(false);
	});

	test("labels are trimmed for matching; values are compared verbatim", () => {
		expect(sameCustomFields([row("a", "1")], [row("  a  ", "1")])).toBe(true);
		// A value's whitespace may be part of the secret — never normalized.
		expect(sameCustomFields([row("a", "1")], [row("a", " 1")])).toBe(false);
	});

	// sameTags precedent: duplicate multiplicity must survive or removing one
	// of two same-label rows would not dirty the form.
	test("duplicate multiplicity is preserved", () => {
		expect(sameCustomFields([row("a", "1"), row("a", "2")], [row("a", "1")])).toBe(
			false,
		);
	});
});

describe("detectChanges custom branch", () => {
	test("added and removed rows emit with empty opposite values", () => {
		expect(
			detectChanges(baseMeta(), null, form(), false, false, false, null),
		).toEqual([]);
		expect(
			detectChanges(
				baseMeta(),
				null,
				form({ custom_fields: [row("token", "t0k3n")] }),
				false,
				false,
				false,
				null,
			),
		).toEqual([
			{
				fieldId: "custom:token",
				label: "token",
				oldValue: "",
				newValue: "t0k3n",
				valueType: "text",
			},
		]);
		expect(
			detectChanges(
				baseMeta(),
				null,
				form(),
				false,
				false,
				false,
				[row("token", "t0k3n")],
			),
		).toEqual([
			{
				fieldId: "custom:token",
				label: "token",
				oldValue: "t0k3n",
				newValue: "",
				valueType: "text",
			},
		]);
	});

	test("modified rows carry old→new; secret rows mask like passwords", () => {
		expect(
			detectChanges(
				baseMeta(),
				null,
				form({ custom_fields: [row("api_key", "new", true)] }),
				false,
				false,
				false,
				[row("api_key", "old", true)],
			),
		).toEqual([
			{
				fieldId: "custom:api_key",
				label: "api_key",
				oldValue: "old",
				newValue: "new",
				valueType: "password",
			},
		]);
	});

	test("reorder and fully blank rows produce no diff", () => {
		expect(
			detectChanges(
				baseMeta(),
				null,
				form({ custom_fields: [row("b", "2", true), row("a", "1")] }),
				false,
				false,
				false,
				[row("a", "1"), row("b", "2", true)],
			),
		).toEqual([]);
		expect(
			detectChanges(
				baseMeta(),
				null,
				form({ custom_fields: [row("", "")] }),
				false,
				false,
				false,
				[],
			),
		).toEqual([]);
	});
});

describe("editor wiring", () => {
	test("new entry: a blank row is not dirty and creates with an empty array", async () => {
		render(<EntryScreen />);
		fillRequiredFields();
		fireEvent.click(screen.getByRole("button", { name: "Add field" }));
		expect(screen.getByLabelText("Field 1 label")).toHaveValue("");

		fireEvent.click(screen.getByRole("button", { name: "Save" }));
		await waitFor(() => expect(createEntry).toHaveBeenCalledOnce());
		expect(createEntry).toHaveBeenCalledWith(
			expect.objectContaining({ custom_fields: [] }),
		);
	});

	test("new entry: filled rows are sent; fully blank rows are filtered", async () => {
		render(<EntryScreen />);
		fillRequiredFields();
		fireEvent.click(screen.getByRole("button", { name: "Add field" }));
		fireEvent.change(screen.getByLabelText("Field 1 label"), {
			target: { value: "token" },
		});
		fireEvent.change(screen.getByLabelText("Field 1 value"), {
			target: { value: "t0k3n" },
		});
		// A second, untouched row must not reach the request.
		fireEvent.click(screen.getByRole("button", { name: "Add field" }));

		fireEvent.click(screen.getByRole("button", { name: "Save" }));
		await waitFor(() => expect(createEntry).toHaveBeenCalledOnce());
		expect(createEntry).toHaveBeenCalledWith(
			expect.objectContaining({
				custom_fields: [row("token", "t0k3n")],
			}),
		);
	});

	test("edit: metadata-only save neither fetches secrets nor touches custom fields", async () => {
		vaultState.selectedEntry = baseMeta({
			custom_fields: [{ label: "api_key", secret: true }],
		});
		render(<EntryScreen />);

		// The stored row renders from the summary metadata, value hidden.
		expect(screen.getByLabelText("Field 1 label")).toHaveValue("api_key");
		expect(screen.getByLabelText("Field 1 value")).toHaveValue("");

		fireEvent.change(screen.getByLabelText("Title *"), {
			target: { value: "After" },
		});
		const patch = await saveAndCapturePatch();

		expect(getEntrySecret).not.toHaveBeenCalled();
		// The load-bearing no-wipe pin: an omitted key means the backend
		// leaves the stored (secret, unseen) values untouched.
		expect(patch).not.toHaveProperty("custom_fields");
	});

	test("edit: adding a row runs the guarded fetch and the replacement preserves stored values", async () => {
		vaultState.selectedEntry = baseMeta({
			custom_fields: [{ label: "api_key", secret: true }],
		});
		getEntrySecret.mockResolvedValue({
			password: "stored-pw",
			notes: "",
			custom_fields: [{ label: "api_key", value: "s3cret", secret: true }],
		});
		render(<EntryScreen />);

		fireEvent.click(screen.getByRole("button", { name: "Add field" }));
		fireEvent.change(screen.getByLabelText("Field 2 label"), {
			target: { value: "token" },
		});
		fireEvent.change(screen.getByLabelText("Field 2 value"), {
			target: { value: "t0k3n" },
		});

		const patch = await saveAndCapturePatch();
		// Exactly one secret fetch: the save-time guard.
		expect(getEntrySecret).toHaveBeenCalledOnce();
		expect(patch.custom_fields).toEqual([
			// The never-seen stored value rides along untouched — no wipe.
			row("api_key", "s3cret", true),
			row("token", "t0k3n"),
		]);
	});

	test("edit: revealing the password fills the rows in the same fetch; untouched save omits them", async () => {
		vaultState.selectedEntry = baseMeta({
			custom_fields: [{ label: "api_key", secret: true }],
		});
		getEntrySecret.mockResolvedValue({
			password: "stored-pw",
			notes: "",
			custom_fields: [{ label: "api_key", value: "s3cret", secret: true }],
		});
		render(<EntryScreen />);

		// The password reveal is the piggyback fetch for field values.
		fireEvent.click(screen.getByRole("button", { name: "Show password" }));
		await waitFor(() =>
			expect(screen.getByLabelText("Field 1 value")).toHaveValue("s3cret"),
		);

		fireEvent.click(screen.getByRole("button", { name: "Save" }));
		await waitFor(() => expect(navigate).toHaveBeenCalledWith("vault"));
		// Nothing changed → no confirmation, no request at all.
		expect(updateEntry).not.toHaveBeenCalled();
		expect(getEntrySecret).toHaveBeenCalledOnce();
	});

	test("edit: an edited value sends the replacement and masks the modal row", async () => {
		vaultState.selectedEntry = baseMeta({
			custom_fields: [{ label: "api_key", secret: true }],
		});
		getEntrySecret.mockResolvedValue({
			password: "stored-pw",
			notes: "",
			custom_fields: [{ label: "api_key", value: "s3cret", secret: true }],
		});
		render(<EntryScreen />);

		fireEvent.click(screen.getByRole("button", { name: "Show password" }));
		await waitFor(() =>
			expect(screen.getByLabelText("Field 1 value")).toHaveValue("s3cret"),
		);
		fireEvent.change(screen.getByLabelText("Field 1 value"), {
			target: { value: "new-secret" },
		});

		fireEvent.click(screen.getByRole("button", { name: "Save" }));
		// The secret row appears in the confirmation under its label…
		expect(await screen.findByText("api_key")).toBeInTheDocument();
		fireEvent.click(screen.getByText("I've reviewed these changes"));
		fireEvent.click(screen.getByRole("button", { name: "Save Changes" }));
		await waitFor(() => expect(updateEntry).toHaveBeenCalledOnce());
		expect(updateEntry.mock.calls[0][1].custom_fields).toEqual([
			row("api_key", "new-secret", true),
		]);
		// The value was loaded by the reveal, not by a second fetch.
		expect(getEntrySecret).toHaveBeenCalledOnce();
	});

	test("edit: a failed guard fetch surfaces the error and never saves", async () => {
		vaultState.selectedEntry = baseMeta({
			custom_fields: [{ label: "api_key", secret: true }],
		});
		getEntrySecret.mockRejectedValue(new Error("locked"));
		render(<EntryScreen />);

		fireEvent.click(screen.getByRole("button", { name: "Add field" }));
		fireEvent.change(screen.getByLabelText("Field 2 label"), {
			target: { value: "token" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Save" }));

		expect(await screen.findByText("Failed to load custom fields")).toBeInTheDocument();
		expect(updateEntry).not.toHaveBeenCalled();
	});

	// v1.6.0 review fixes: the per-row secret switch (lock) lets the desktop
	// CREATE secret rows — previously impossible from this form.
	test("new entry: the lock toggle marks a row secret; the payload strips the row id", async () => {
		render(<EntryScreen />);
		fillRequiredFields();
		fireEvent.click(screen.getByRole("button", { name: "Add field" }));
		fireEvent.change(screen.getByLabelText("Field 1 label"), {
			target: { value: "api_key" },
		});
		fireEvent.change(screen.getByLabelText("Field 1 value"), {
			target: { value: "s3cret" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Mark field 1 as secret" }));

		fireEvent.click(screen.getByRole("button", { name: "Save" }));
		await waitFor(() => expect(createEntry).toHaveBeenCalledOnce());
		expect(createEntry).toHaveBeenCalledWith(
			expect.objectContaining({
				custom_fields: [row("api_key", "s3cret", true)],
			}),
		);
		// The UI-internal row id never reaches the IPC payload.
		expect(createEntry.mock.calls[0][0].custom_fields[0]).not.toHaveProperty("id");
	});

	test("edit: flipping a stored row's secret flag dirties and replaces", async () => {
		vaultState.selectedEntry = baseMeta({
			custom_fields: [{ label: "region", secret: false }],
		});
		getEntrySecret.mockResolvedValue({
			password: "stored-pw",
			notes: "",
			custom_fields: [{ label: "region", value: "us", secret: false }],
		});
		render(<EntryScreen />);

		fireEvent.click(screen.getByRole("button", { name: "Mark field 1 as secret" }));

		const patch = await saveAndCapturePatch();
		// The flag flip alone dirties the form → the guarded fetch ran once
		// and the replacement carries the loaded value under the new flag.
		expect(getEntrySecret).toHaveBeenCalledOnce();
		expect(patch.custom_fields).toEqual([row("region", "us", true)]);
	});

	// P3 fix: the guarded fetch must hold the same re-entry lock as create —
	// a second Save click while it is in flight is a no-op.
	test("save holds the busy lock while the guarded fetch runs", async () => {
		vaultState.selectedEntry = baseMeta({
			custom_fields: [{ label: "api_key", secret: true }],
		});
		let releaseFetch: (() => void) | null = null;
		getEntrySecret.mockImplementation(
			() =>
				new Promise((resolve) => {
					releaseFetch = () =>
						resolve({
							password: "stored-pw",
							notes: "",
							custom_fields: [
								{ label: "api_key", value: "s3cret", secret: true },
							],
						});
				}),
		);
		render(<EntryScreen />);

		fireEvent.click(screen.getByRole("button", { name: "Add field" }));
		fireEvent.change(screen.getByLabelText("Field 2 label"), {
			target: { value: "token" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Save" }));
		await waitFor(() => expect(getEntrySecret).toHaveBeenCalledOnce());

		// Mid-fetch: the Save button is locked and a second click is inert.
		const save = screen.getByRole("button", { name: /Saving|Save/ });
		expect(save).toBeDisabled();
		fireEvent.click(save);
		expect(getEntrySecret).toHaveBeenCalledOnce(); // still exactly one

		releaseFetch?.();
		fireEvent.click(await screen.findByText("I've reviewed these changes"));
		fireEvent.click(screen.getByRole("button", { name: "Save Changes" }));
		await waitFor(() => expect(updateEntry).toHaveBeenCalledOnce());
		expect(updateEntry.mock.calls[0][1].custom_fields).toEqual([
			row("api_key", "s3cret", true),
			row("token", ""),
		]);
	});

	// P3 fix: an entry with NO stored fields skips the guard fetch — there is
	// nothing to protect and the fetch would only spend a round trip.
	test("adding rows to an entry without stored fields skips the guard fetch", async () => {
		vaultState.selectedEntry = baseMeta();
		render(<EntryScreen />);

		fireEvent.click(screen.getByRole("button", { name: "Add field" }));
		fireEvent.change(screen.getByLabelText("Field 1 label"), {
			target: { value: "token" },
		});
		fireEvent.change(screen.getByLabelText("Field 1 value"), {
			target: { value: "t0k3n" },
		});

		const patch = await saveAndCapturePatch();
		expect(getEntrySecret).not.toHaveBeenCalled();
		expect(patch.custom_fields).toEqual([row("token", "t0k3n")]);
	});

	// P3 fix (CQ-P2a precedent): a failed create surfaces the desktop's real
	// error instead of the generic "Failed to create entry".
	test("create failure surfaces the desktop error, not a generic message", async () => {
		createEntry.mockRejectedValue(new Error("duplicate label rejected"));
		render(<EntryScreen />);
		fillRequiredFields();

		fireEvent.click(screen.getByRole("button", { name: "Save" }));
		expect(
			await screen.findByText("duplicate label rejected"),
		).toBeInTheDocument();
	});
});
