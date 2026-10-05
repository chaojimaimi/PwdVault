import { fireEvent, render, screen } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import { TagsEditor } from "./TagsEditor";

test("renders chips and removes a tag through onChange", () => {
	const onChange = vi.fn();
	render(<TagsEditor value={["work", "email"]} onChange={onChange} />);

	expect(screen.getByText("work ×")).toBeInTheDocument();
	expect(screen.getByText("email ×")).toBeInTheDocument();
	fireEvent.click(screen.getByRole("button", { name: "Remove tag work" }));
	expect(onChange).toHaveBeenCalledWith(["email"]);
});

test("Enter adds a trimmed unique tag; duplicates keep the input text", () => {
	const onChange = vi.fn();
	render(<TagsEditor value={["work"]} onChange={onChange} />);

	const input = screen.getByPlaceholderText("Add tag...");
	fireEvent.change(input, { target: { value: "  web  " } });
	fireEvent.keyDown(input, { key: "Enter" });
	expect(onChange).toHaveBeenCalledWith(["work", "web"]);

	// Re-adding an existing tag must neither fire onChange nor clear the
	// input (same semantics as the original inline editor).
	fireEvent.change(input, { target: { value: "work" } });
	fireEvent.keyDown(input, { key: "Enter" });
	expect(onChange).toHaveBeenCalledTimes(1);
	expect(input).toHaveValue("work");
});
