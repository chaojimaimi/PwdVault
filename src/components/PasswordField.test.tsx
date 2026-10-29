import { render, fireEvent, screen } from "@testing-library/react";
import { vi, describe, it, expect } from "vitest";
import { PasswordField } from "./PasswordField";

describe("PasswordField", () => {
	it("associates the label with the input and forwards typed values", () => {
		const onChange = vi.fn();
		render(
			<PasswordField id="pw" label="Master password" value="" onChange={onChange} />,
		);

		const input = screen.getByLabelText("Master password");
		expect(input).toHaveAttribute("type", "password");
		fireEvent.change(input, { target: { value: "hunter2" } });
		expect(onChange).toHaveBeenCalledWith("hunter2");
	});

	it("toggles visibility through the Show/Hide password eye button", () => {
		render(
			<PasswordField id="pw" label="Master password" value="hunter2" onChange={() => {}} />,
		);

		const input = screen.getByLabelText("Master password");
		expect(input).toHaveAttribute("type", "password");

		fireEvent.click(screen.getByRole("button", { name: "Show password" }));
		expect(screen.getByLabelText("Master password")).toHaveAttribute("type", "text");
		expect(screen.getByRole("button", { name: "Hide password" })).toBeInTheDocument();

		fireEvent.click(screen.getByRole("button", { name: "Hide password" }));
		expect(screen.getByLabelText("Master password")).toHaveAttribute("type", "password");
		expect(screen.getByRole("button", { name: "Show password" })).toBeInTheDocument();
	});

	it("wires aria-invalid and aria-describedby through to the input", () => {
		render(
			<PasswordField
				id="pw"
				label="Master password"
				value=""
				onChange={() => {}}
				ariaInvalid
				ariaDescribedBy="pw-error"
			/>,
		);

		const input = screen.getByLabelText("Master password");
		expect(input).toHaveAttribute("aria-invalid", "true");
		expect(input).toHaveAttribute("aria-describedby", "pw-error");
	});
});
