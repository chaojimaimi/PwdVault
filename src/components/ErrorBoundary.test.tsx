import { render, fireEvent, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { ErrorBoundary } from "./ErrorBoundary";

const relaunch = vi.fn();
const writeText = vi.fn().mockResolvedValue(undefined);

vi.mock("@tauri-apps/plugin-process", () => ({
	relaunch: (...args: unknown[]) => relaunch(...args),
}));

function Bomb({ explode }: { explode: boolean }): ReactNode {
	if (explode) {
		throw new Error("render exploded");
	}
	return null;
}

beforeEach(() => {
	vi.clearAllMocks();
	// React logs caught render errors through console.error; keep the test
	// output clean and assert-free of the expected noise.
	vi.spyOn(console, "error").mockImplementation(() => {});
	Object.defineProperty(navigator, "clipboard", {
		value: { writeText },
		configurable: true,
	});
});

afterEach(() => {
	vi.restoreAllMocks();
});

describe("ErrorBoundary", () => {
	it("renders the fallback when a child throws during render", () => {
		render(
			<ErrorBoundary>
				<Bomb explode />
			</ErrorBoundary>,
		);

		expect(screen.getByRole("alert")).toBeInTheDocument();
		expect(screen.getByText("Something went wrong")).toBeInTheDocument();
		expect(screen.getByText("render exploded")).toBeInTheDocument();
	});

	it("restarts the app when the restart button is clicked", () => {
		render(
			<ErrorBoundary>
				<Bomb explode />
			</ErrorBoundary>,
		);

		fireEvent.click(
			screen.getByRole("button", { name: "Restart App" }),
		);
		expect(relaunch).toHaveBeenCalledTimes(1);
	});

	it("copies the error details best-effort when the copy button is clicked", async () => {
		render(
			<ErrorBoundary>
				<Bomb explode />
			</ErrorBoundary>,
		);

		fireEvent.click(
			screen.getByRole("button", { name: "Copy Error Details" }),
		);
		await vi.waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
		expect(writeText).toHaveBeenCalledWith(
			expect.stringContaining("render exploded"),
		);
	});
});
