import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, test, vi } from "vitest";
import EntryScreen from "../EntryScreen";

const getEntrySecret = vi.fn();
const updateEntry = vi.fn().mockResolvedValue({});
const navigate = vi.fn();
const selectEntry = vi.fn();
const deleteEntry = vi.fn();
const createEntry = vi.fn();
const totpCode = vi.fn();

// Stable state/actions objects so React's useEffect dependency check does not
// see a new `selectedEntry` reference on every render (which would loop).
const vaultState = {
	selectedEntry: {
		id: "entry-1",
		title: "Before",
		username: "user",
		url: "",
		tags: [],
		group_id: null,
		created_at: 1,
		updated_at: 1,
	},
};
const vaultActions = {
	getEntrySecret,
	updateEntry,
	selectEntry,
	deleteEntry,
	createEntry,
};
const authActions = { navigate };

vi.mock("../../context/AppContext", () => ({
	useAuth: () => ({ actions: authActions }),
	useVault: () => ({ state: vaultState, actions: vaultActions }),
	useSettings: () => ({ state: { settings: {} }, actions: {} }),
}));
vi.mock("../../api/vault", () => ({
	totpCode: (...args: unknown[]) => totpCode(...args),
}));
vi.mock("../../components/GroupSelector", () => ({
	default: () => <div data-testid="group-selector" />,
}));

beforeEach(() => {
	vi.clearAllMocks();
	updateEntry.mockResolvedValue({});
	// Entry has no TOTP configured: the backend answers TOTP_NOT_CONFIGURED
	// and the live-code view hides itself.
	totpCode.mockRejectedValue({
		InvalidInput: { code: "TOTP_NOT_CONFIGURED", message: "no secret" },
	});
});

async function saveAndCapturePatch() {
	fireEvent.click(screen.getByRole("button", { name: "Save" }));
	fireEvent.click(screen.getByText("I've reviewed these changes"));
	fireEvent.click(screen.getByRole("button", { name: "Save Changes" }));
	await waitFor(() => expect(updateEntry).toHaveBeenCalledOnce());
	return updateEntry.mock.calls[0][1];
}

test("TOTP field is present in edit mode with the otpauth hint", () => {
	render(<EntryScreen />);
	expect(screen.getByLabelText("TOTP Secret")).toBeInTheDocument();
	expect(
		screen.getByText(/Paste a base32 secret or a full otpauth:\/\//),
	).toBeInTheDocument();
});

test("untouched TOTP field sends no totp_secret (leave unchanged)", async () => {
	render(<EntryScreen />);
	fireEvent.change(screen.getByLabelText("Title *"), {
		target: { value: "After" },
	});
	const patch = await saveAndCapturePatch();
	expect(patch).not.toHaveProperty("totp_secret");
});

test("entering a secret sends totp_secret (set) and masks it in the confirm list", async () => {
	render(<EntryScreen />);
	fireEvent.change(screen.getByLabelText("TOTP Secret"), {
		target: { value: "JBSWY3DPEHPK3PXP" },
	});
	fireEvent.click(screen.getByRole("button", { name: "Save" }));
	// The confirmation modal reports the change without revealing the value:
	// one match for the form label, one for the modal's change row.
	expect(screen.getAllByText("TOTP Secret").length).toBeGreaterThanOrEqual(2);
	fireEvent.click(screen.getByText("I've reviewed these changes"));
	fireEvent.click(screen.getByRole("button", { name: "Save Changes" }));
	await waitFor(() => expect(updateEntry).toHaveBeenCalledOnce());
	expect(updateEntry.mock.calls[0][1].totp_secret).toBe("JBSWY3DPEHPK3PXP");
});

test("clearing the field sends an empty totp_secret (remove)", async () => {
	render(<EntryScreen />);
	const field = screen.getByLabelText("TOTP Secret");
	fireEvent.change(field, { target: { value: "JBSWY3DPEHPK3PXP" } });
	fireEvent.change(field, { target: { value: "" } });
	const patch = await saveAndCapturePatch();
	expect(patch.totp_secret).toBe("");
});

test("pasting an otpauth:// URI shows the detected hint and is kept as-is", async () => {
	render(<EntryScreen />);
	const uri = "otpauth://totp/acme?secret=JBSWY3DPEHPK3PXP&issuer=acme";
	fireEvent.change(screen.getByLabelText("TOTP Secret"), {
		target: { value: uri },
	});
	expect(screen.getByText(/otpauth:\/\/ URI detected/)).toBeInTheDocument();
	const patch = await saveAndCapturePatch();
	expect(patch.totp_secret).toBe(uri);
});
