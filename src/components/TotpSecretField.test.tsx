import { fireEvent, render, screen } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import { TotpSecretField } from "./TotpSecretField";

// The live-code view is its own component with backend polling; stub it so
// this suite stays a pure render test of the secret field itself.
vi.mock("./TotpCode", () => ({
	TotpCode: () => <div data-testid="totp-code" />,
}));

test("renders the live-code slot, a masked field, and the base32 hint", () => {
	const onChangeValue = vi.fn();
	render(
		<TotpSecretField
			entryId="entry-1"
			value=""
			visible={false}
			onChangeValue={onChangeValue}
			onToggleVisible={() => {}}
		/>,
	);
	expect(screen.getByTestId("totp-code")).toBeInTheDocument();
	const input = screen.getByLabelText("TOTP Secret");
	expect(input).toHaveAttribute("type", "password");
	expect(
		screen.getByText(/Paste a base32 secret or a full otpauth:\/\//),
	).toBeInTheDocument();

	fireEvent.change(input, { target: { value: "JBSWY3DPEHPK3PXP" } });
	expect(onChangeValue).toHaveBeenCalledWith("JBSWY3DPEHPK3PXP");
});

test("detects otpauth URIs and toggles visibility through the parent", () => {
	const onToggleVisible = vi.fn();
	render(
		<TotpSecretField
			entryId="entry-1"
			value="otpauth://totp/acme?secret=JBSWY3DPEHPK3PXP"
			visible={true}
			onChangeValue={() => {}}
			onToggleVisible={onToggleVisible}
		/>,
	);
	expect(screen.getByText(/otpauth:\/\/ URI detected/)).toBeInTheDocument();
	expect(screen.getByLabelText("TOTP Secret")).toHaveAttribute("type", "text");

	fireEvent.click(screen.getByRole("button", { name: "Hide TOTP secret" }));
	expect(onToggleVisible).toHaveBeenCalledOnce();
});
