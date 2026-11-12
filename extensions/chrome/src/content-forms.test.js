// v1.8.3 F3: auto-fill visibility gating — credentials must never land in
// fields the page does not render (honeypot pages place display:none
// password fields first and read whatever automation pours into them).
//
// First behavioral test for a single content file: loaded like
// clipboard-clear.test.js — vite.config.ts runs the suite under jsdom, so a
// direct import of the IIFE module works and assertions read through the
// globalThis.PwdVaultContent namespace (the six-file content consortium
// itself stays covered by the source-text contract tests). jsdom has no
// checkVisibility, so every case here exercises the computed-style
// fallback with inline styles — never rect/offsetParent (all-zero in
// jsdom, they would reject everything).
import { afterEach, describe, expect, it } from "vitest";
import "./content-forms.js";

const NS = () => globalThis.PwdVaultContent;

afterEach(() => {
	document.body.innerHTML = "";
});

describe("content-forms visibility gating (v1.8.3 F3)", () => {
	it("selects the visible field in a honeypot layout (hidden first)", () => {
		document.body.innerHTML = `
			<form>
				<input type="password" name="honeypot" style="display: none">
				<input type="password" name="pwd">
				<input type="text" name="username">
			</form>`;

		const form = NS().findLoginForm();
		expect(form.passwordField).toBe(
			document.querySelector('input[name="pwd"]'),
		);
	});

	it("ranks visibility above the autocomplete=current-password hint", () => {
		document.body.innerHTML = `
			<form>
				<input type="password" name="trap" autocomplete="current-password" style="display: none">
				<input type="password" name="pwd">
			</form>`;

		const form = NS().findLoginForm();
		expect(form.passwordField).toBe(
			document.querySelector('input[name="pwd"]'),
		);
	});

	it("reports no login form when every password field is hidden", () => {
		document.body.innerHTML = `
			<form>
				<input type="password" name="hp1" style="display: none">
				<input type="password" name="hp2" style="visibility: hidden">
			</form>`;

		// Fail-safe: autofillLogin turns this into "No login form detected"
		// instead of filling an unrendered field.
		expect(NS().findLoginForm()).toBeNull();
	});

	it("skips hidden username candidates and still picks the visible one", () => {
		document.body.innerHTML = `
			<form>
				<input type="text" name="username" value="ghost" style="display: none">
				<input type="text" name="mail" value="real">
				<input type="password" name="pwd">
			</form>`;

		const form = NS().findLoginForm();
		// The hidden candidate scores higher on name patterns, so without the
		// gate the ghost input would win; the gate must exclude it up front.
		expect(form.usernameField).toBe(
			document.querySelector('input[name="mail"]'),
		);
		expect(form.usernameField.value).toBe("real");
	});

	it("captures only a visible field on the save-prompt path", () => {
		document.body.innerHTML = `
			<form>
				<input type="password" name="honeypot" value="s3cret" style="display: none">
				<input type="password" name="pwd" value="s3cret">
			</form>`;

		// content-save-prompt.credentialsInForm hands the raw array to
		// selectPasswordField — the gate must hold at selection time too.
		const inputs = Array.from(
			document.querySelectorAll('input[type="password"]'),
		);
		const picked = NS().selectPasswordField(inputs);
		expect(picked).toBe(document.querySelector('input[name="pwd"]'));
		expect(picked.value).toBe("s3cret");

		// All-hidden layout: nothing capturable (the save prompt's
		// `if (!passwordInput) return null` then skips the capture).
		document.body.innerHTML = `
			<form>
				<input type="password" name="honeypot" value="s3cret" style="display: none">
			</form>`;
		const hiddenOnly = Array.from(
			document.querySelectorAll('input[type="password"]'),
		);
		expect(NS().selectPasswordField(hiddenOnly)).toBeUndefined();
	});
});
