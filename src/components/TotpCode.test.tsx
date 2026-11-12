import { render, fireEvent, screen, waitFor, act } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import { TotpCode } from "./TotpCode";
import { copyWithTimeout } from "../utils/clipboard";
import { showToast } from "../utils/toast";

vi.mock("../utils/toast", () => ({ showToast: vi.fn() }));
vi.mock("../utils/clipboard", () => ({ copyWithTimeout: vi.fn() }));

const totpCode = vi.fn();

vi.mock("../api/vault", () => ({
	totpCode: (...args: unknown[]) => totpCode(...args),
}));

beforeEach(() => {
	vi.clearAllMocks();
	vi.mocked(copyWithTimeout).mockResolvedValue(undefined);
});

describe("TotpCode", () => {
	it("renders the current code with the countdown and copies it", async () => {
		totpCode.mockResolvedValue({ code: "123456", seconds_remaining: 18 });
		render(<TotpCode entryId="entry-1" />);

		expect(await screen.findByText("123456")).toBeInTheDocument();
		expect(totpCode).toHaveBeenCalledWith("entry-1");
		expect(screen.getByText("18s")).toBeInTheDocument();

		fireEvent.click(screen.getByRole("button", { name: "Copy TOTP code" }));
		await waitFor(() =>
			expect(copyWithTimeout).toHaveBeenCalledWith("123456"),
		);
		expect(showToast).toHaveBeenCalledWith(
			expect.stringContaining("TOTP code copied"),
		);
	});

	// v1.8.4 (P3-3): a clipboard failure must be visible — toast the failure,
	// never claim the copy succeeded, and no unhandled rejection escapes the
	// void-ed onClick (vitest fails the run on unhandled rejections, so this
	// case doubles as the no-rejection pin).
	it("toasts a failure instead of claiming success when the clipboard write fails", async () => {
		totpCode.mockResolvedValue({ code: "123456", seconds_remaining: 18 });
		vi.mocked(copyWithTimeout).mockRejectedValue(
			new Error("clipboard blocked"),
		);
		render(<TotpCode entryId="entry-1" />);
		await screen.findByText("123456");

		fireEvent.click(screen.getByRole("button", { name: "Copy TOTP code" }));

		await waitFor(() =>
			expect(showToast).toHaveBeenCalledWith("Failed to copy TOTP code"),
		);
		expect(showToast).not.toHaveBeenCalledWith(
			expect.stringContaining("copied"),
		);
	});

	it("renders nothing while the entry has no configured secret", async () => {
		// v1.3.2: VaultError reaches the UI as its public-message string
		// ("CODE: message") — same shape the HTTP path always had.
		totpCode.mockRejectedValue("TOTP_NOT_CONFIGURED: no secret");
		const { container } = render(<TotpCode entryId="entry-1" />);

		await waitFor(() => expect(totpCode).toHaveBeenCalledOnce());
		expect(container).toBeEmptyDOMElement();
	});

	it("retries after a transient failure instead of wedging at zero", async () => {
		vi.useFakeTimers();
		try {
			totpCode.mockRejectedValueOnce("Internal error");
			totpCode.mockResolvedValue({ code: "654321", seconds_remaining: 12 });
			render(<TotpCode entryId="entry-1" />);

			// First fetch fails (transient) — the badge hides, nothing renders.
			await act(async () => {});
			expect(totpCode).toHaveBeenCalledTimes(1);
			expect(screen.queryByText(/s$/)).not.toBeInTheDocument();

			// The retry countdown ticks down; hitting zero triggers one refetch,
			// which now succeeds and shows the code.
			await act(async () => {
				vi.advanceTimersByTime(6000);
			});
			await act(async () => {});
			expect(totpCode).toHaveBeenCalledTimes(2);
			expect(screen.getByText("654321")).toBeInTheDocument();
		} finally {
			vi.useRealTimers();
		}
	});

	it("stops polling entirely on TOTP_NOT_CONFIGURED (permanent)", async () => {
		vi.useFakeTimers();
		try {
			totpCode.mockRejectedValue("TOTP_NOT_CONFIGURED: no secret");
			const { container } = render(<TotpCode entryId="entry-1" />);

			await act(async () => {});
			await act(async () => {
				vi.advanceTimersByTime(60000);
			});
			await act(async () => {});
			expect(totpCode).toHaveBeenCalledOnce();
			expect(container).toBeEmptyDOMElement();
		} finally {
			vi.useRealTimers();
		}
	});
});
