import React from "react";
import { render, fireEvent, screen, waitFor } from "@testing-library/react";
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

	it("renders nothing while the entry has no configured secret", async () => {
		totpCode.mockRejectedValue({
			InvalidInput: { code: "TOTP_NOT_CONFIGURED", message: "no secret" },
		});
		const { container } = render(<TotpCode entryId="entry-1" />);

		await waitFor(() => expect(totpCode).toHaveBeenCalledOnce());
		expect(container).toBeEmptyDOMElement();
	});
});
