import { render } from "@testing-library/react";
import { vi, test, expect } from "vitest";
import EntryScreen from "../EntryScreen";

// Lightweight smoke test: EntryScreen mounts without crashing when its
// contexts return empty state. Detailed confirmation behaviour is covered
// by EntryScreen.secretBoundary.test.tsx.
vi.mock("../../context/AppContext", () => ({
	useAuth: () => ({ actions: { navigate: vi.fn() } }),
	useVault: () => ({
		state: { selectedEntry: null },
		actions: {
			selectEntry: vi.fn(),
			createEntry: vi.fn(),
			updateEntry: vi.fn(),
			deleteEntry: vi.fn(),
			getEntrySecret: vi.fn(),
		},
	}),
	useSettings: () => ({ state: { settings: {} }, actions: {} }),
}));
vi.mock("../../components/GroupSelector", () => ({ default: () => null }));

test("EntryScreen mounts in the new-entry state", () => {
	const { container } = render(<EntryScreen />);
	expect(container).toBeTruthy();
});
