import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, test, vi } from "vitest";
import { EntryScreen } from "../EntryScreen";

// v1.3.2 form semantics: the entry content area is a real <form> and the
// Save button (outside it, in .entry-actions) is its associated submit
// button via the form= attribute. Contract under test:
//   1. Enter in a text field runs implicit submission → handleSave;
//   2. Enter in the Tags input only adds the tag (preventDefault) and does
//      NOT submit;
//   3. clicking Delete (type="button", outside the form) never submits.

const getEntrySecret = vi.fn();
const updateEntry = vi.fn().mockResolvedValue({});
const createEntry = vi.fn();
const deleteEntry = vi.fn();
const navigate = vi.fn();
const selectEntry = vi.fn();

// New-entry mode (selectedEntry === null): save goes straight through
// createEntry, which is the observable "submitted" signal. The Delete test
// temporarily flips to edit mode.
const vaultState: { selectedEntry: Record<string, unknown> | null } = {
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
vi.mock("../../api/vault", () => ({
	generatePassword: vi.fn(),
}));
vi.mock("../../components/GroupSelector", () => ({
	default: () => <div data-testid="group-selector" />,
}));

beforeEach(() => {
	vi.clearAllMocks();
	createEntry.mockResolvedValue({
		id: "new-1",
		title: "T",
		username: "u",
		tags: [],
		created_at: 1,
		updated_at: 1,
	});
});

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

test("the associated Save submit button runs exactly one save", async () => {
	// Real browsers run Enter-in-a-text-field as "click the form's default
	// button" (implicit submission) — jsdom does not implement that, so this
	// drives the same activation path directly: a click on the type=submit
	// button associated via form=. The type/form attributes are also asserted
	// because they are what makes Enter submit in a real browser.
	render(<EntryScreen />);
	fillRequiredFields();

	const save = screen.getByRole("button", { name: "Save" });
	expect(save).toHaveAttribute("type", "submit");
	expect(save).toHaveAttribute("form", "pwdvault-entry-form");

	fireEvent.click(save);

	await waitFor(() => expect(createEntry).toHaveBeenCalledOnce());
	// One activation → one submit event → one save (no double-fire).
	expect(createEntry).toHaveBeenCalledTimes(1);
	expect(createEntry).toHaveBeenCalledWith(
		expect.objectContaining({
			title: "Example",
			username: "user@example.com",
		}),
	);
});

test("Enter in the Tags input adds the tag without submitting", async () => {
	render(<EntryScreen />);
	fillRequiredFields();

	const tagInput = screen.getByLabelText("Tags", { selector: "input" });
	fireEvent.change(tagInput, { target: { value: "work" } });
	// fireEvent resolves to false when preventDefault was called — the tag
	// handler must swallow the Enter so the form never sees it.
	const notPrevented = fireEvent.keyDown(tagInput, { key: "Enter" });
	expect(notPrevented).toBe(false);

	// The tag chip appears…
	expect(screen.getByRole("button", { name: "Remove tag work" })).toBeInTheDocument();
	// …but the form was NOT submitted.
	expect(createEntry).not.toHaveBeenCalled();
	expect(navigate).not.toHaveBeenCalled();
});

test("clicking Delete does not submit the form", async () => {
	// Edit mode: the Delete button only exists there.
	vaultState.selectedEntry = {
		id: "entry-1",
		title: "Before",
		username: "user",
		url: "",
		tags: [],
		group_id: null,
		created_at: 1,
		updated_at: 1,
	};
	try {
		render(<EntryScreen />);

		fireEvent.click(screen.getByRole("button", { name: "Delete" }));

		// Delete opens its confirm modal instead of running the save path.
		expect(await screen.findByText(/Are you sure you want to delete/)).toBeInTheDocument();
		expect(updateEntry).not.toHaveBeenCalled();
		expect(createEntry).not.toHaveBeenCalled();
	} finally {
		vaultState.selectedEntry = null;
	}
});
