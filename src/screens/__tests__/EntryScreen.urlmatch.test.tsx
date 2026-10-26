import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { detectChanges, EntryScreen } from "../EntryScreen";
import {
	normalizeMatchMode,
	URL_MATCH_MODE_OPTIONS,
} from "../../utils/urlMatchMode";
import type { CreateEntryRequest, EntrySummary } from "../../types";

// v1.5.0 WP4: the per-entry URL match override — the select in the URL
// group, the detectChanges ChangeItem branch, and the save-payload plumbing.
// The pure-function matrix drives the exported detectChanges directly
// (sameTags precedent); the render tests pin the select + hint + payload.

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

afterEach(() => {
	// Full reset (v1.4.1 lesson: partial beforeEach resets leak state across
	// test cases).
	vaultState.selectedEntry = null;
});

function baseMeta(overrides: Partial<EntrySummary> = {}): EntrySummary {
	return {
		id: "entry-1",
		title: "Example",
		url: "https://example.com",
		username: "user",
		tags: [],
		group_id: null,
		created_at: 1,
		updated_at: 1,
		...overrides,
	};
}

test("normalizeMatchMode maps absent to auto and keeps known values", () => {
	expect(normalizeMatchMode(undefined)).toBe("auto");
	expect(normalizeMatchMode("auto")).toBe("auto");
	expect(normalizeMatchMode("exact")).toBe("exact");
	expect(normalizeMatchMode("domain")).toBe("domain");
});

test("detectChanges: changing the match mode emits a labeled ChangeItem", () => {
	const changes = detectChanges(
		baseMeta({ url_match_mode: "auto" }),
		null,
		{ title: "Example", url: "https://example.com", username: "user", password: "", notes: "", tags: [], group_id: null, url_match_mode: "exact" },
		false,
		false,
		false,
		// v1.6.0: loaded custom-field values (null = secret channel never ran).
		null,
	);
	expect(changes).toEqual([
		{
			fieldId: "url_match_mode",
			label: "URL Match",
			oldValue: URL_MATCH_MODE_OPTIONS[0].label,
			newValue: URL_MATCH_MODE_OPTIONS[1].label,
			valueType: "text",
		},
	]);
});

test("detectChanges: absent original mode reads as auto (no phantom change)", () => {
	const changes = detectChanges(
		// Pre-v1.5.0 summary: no url_match_mode on the wire.
		baseMeta({ url_match_mode: undefined }),
		null,
		{ title: "Example", url: "https://example.com", username: "user", password: "", notes: "", tags: [], group_id: null, url_match_mode: "auto" },
		false,
		false,
		false,
		// v1.6.0: loaded custom-field values (null = secret channel never ran).
		null,
	);
	expect(changes).toEqual([]);
});

test("detectChanges: auto→domain→auto round trip flips the item twice, not zero", () => {
	const form = (mode: CreateEntryRequest["url_match_mode"]): CreateEntryRequest => ({
		title: "Example",
		url: "https://example.com",
		username: "user",
		password: "",
		notes: "",
		tags: [],
		group_id: null,
		url_match_mode: mode,
	});
	const original = baseMeta({ url_match_mode: "auto" });
	expect(detectChanges(original, null, form("domain"), false, false, false, null)).toHaveLength(1);
	expect(detectChanges(baseMeta({ url_match_mode: "domain" }), null, form("domain"), false, false, false, null)).toEqual([]);
});

test("the URL group renders the three modes and updates its hint", () => {
	render(<EntryScreen />);
	const select = screen.getByLabelText("Browser autofill matches") as HTMLSelectElement;
	expect(select.value).toBe("auto");
	const values = Array.from(select.options).map((o) => o.value);
	expect(values).toEqual(["auto", "exact", "domain"]);

	expect(screen.getByText(/subdomains of the stored URL/i)).toBeInTheDocument();

	fireEvent.change(select, { target: { value: "exact" } });
	expect(select.value).toBe("exact");
	expect(screen.getByText(/only on exactly this host/i)).toBeInTheDocument();
});

test("creating an entry sends the selected match mode", async () => {
	render(<EntryScreen />);
	fireEvent.change(screen.getByLabelText("Title *"), { target: { value: "Example" } });
	fireEvent.change(screen.getByLabelText("Username *"), { target: { value: "user@example.com" } });
	fireEvent.change(screen.getByLabelText("Password *"), { target: { value: "secret-password-1" } });
	fireEvent.change(screen.getByLabelText("Browser autofill matches"), { target: { value: "domain" } });

	fireEvent.click(screen.getByRole("button", { name: "Save" }));

	await waitFor(() => expect(createEntry).toHaveBeenCalledOnce());
	expect(createEntry).toHaveBeenCalledWith(
		expect.objectContaining({ url_match_mode: "domain" }),
	);
});

test("editing only the match mode opens the confirmation with the URL Match row", async () => {
	vaultState.selectedEntry = baseMeta({ url_match_mode: "auto" });
	render(<EntryScreen />);

	fireEvent.change(screen.getByLabelText("Browser autofill matches"), { target: { value: "exact" } });
	fireEvent.click(screen.getByRole("button", { name: "Save" }));

	// metadataDirty must be true (mode change alone) and the modal shows the
	// labeled change instead of silently dropping it. The modal gates its
	// confirm button behind the review checkbox (secretBoundary precedent).
	expect(await screen.findByText("URL Match")).toBeInTheDocument();
	fireEvent.click(screen.getByText("I've reviewed these changes"));
	fireEvent.click(screen.getByRole("button", { name: "Save Changes" }));
	await waitFor(() => expect(updateEntry).toHaveBeenCalledOnce());
	expect(updateEntry).toHaveBeenCalledWith(
		"entry-1",
		expect.objectContaining({ url_match_mode: "exact" }),
	);
});
