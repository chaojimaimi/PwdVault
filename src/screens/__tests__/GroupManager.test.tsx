import React from "react";
import { render, fireEvent, screen, waitFor } from "@testing-library/react";
import { vi, afterEach, describe, it, expect } from "vitest";

const groups = [
	{ id: "g1", name: "Work", created_at: 1, updated_at: 1 },
	{ id: "g2", name: "Personal", created_at: 1, updated_at: 1 },
];

const loadGroups = vi.fn();
const createGroup = vi.fn();
const updateGroup = vi.fn();
const deleteGroup = vi.fn();
const navigate = vi.fn();

// GroupManager now subscribes to useAuth (navigate) and useVault (groups + CRUD).
vi.mock("../../context/AppContext", () => ({
	useAuth: () => ({ actions: { navigate } }),
	useVault: () => {
		// Read the live groups from the module-level variable so each test can
		// mutate it before rendering.
		return {
			state: { groups, entries: [], selectedGroupId: null },
			dispatch: () => {},
			actions: { loadGroups, createGroup, updateGroup, deleteGroup },
		};
	},
	useSettings: () => ({ state: { settings: {} }, actions: {} }),
}));

afterEach(() => {
	vi.resetAllMocks();
});

describe("GroupManager", () => {
	it("renders groups and calls createGroup via inline input", async () => {
		const GroupManager = (await import("../GroupManager")).default;
		render(<GroupManager />);

		await screen.findByText("Work");
		await screen.findByText("Personal");

		const newBtn = screen.getByTitle("New group");
		fireEvent.click(newBtn);

		const input = await screen.findByPlaceholderText("New group name...");
		fireEvent.change(input, { target: { value: "NewGroup" } });

		const createBtn = screen.getByText("Create");
		fireEvent.click(createBtn);

		await waitFor(() => expect(createGroup).toHaveBeenCalledWith("NewGroup"));
	});

	it("renames a group when Save is clicked", async () => {
		const GroupManager = (await import("../GroupManager")).default;
		render(<GroupManager />);

		const renameButtons = await screen.findAllByTitle("Rename");
		fireEvent.click(renameButtons[0]);

		const input = (await screen.findByDisplayValue("Work")) as HTMLInputElement;
		fireEvent.change(input, { target: { value: "WorkRenamed" } });

		const saveBtn = await screen.findByText("Save");
		fireEvent.click(saveBtn);

		await waitFor(() =>
			expect(updateGroup).toHaveBeenCalledWith("g1", "WorkRenamed"),
		);
	});

	it("deletes a group when confirmed", async () => {
		const GroupManager = (await import("../GroupManager")).default;
		render(<GroupManager />);

		const deleteButtons = await screen.findAllByTitle("Delete");
		fireEvent.click(deleteButtons[1]);

		await screen.findByText(/Delete group/);
		const modalDeleteBtn = screen.getAllByText("Delete").pop()!;
		fireEvent.click(modalDeleteBtn);

		await waitFor(() => expect(deleteGroup).toHaveBeenCalledWith("g2"));
	});
});
