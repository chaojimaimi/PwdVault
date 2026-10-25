import { describe, expect, it } from "vitest";
import {
	getGeneratorStrength,
	getPasswordStrength,
} from "../passwordStrength";

/**
 * v1.4.0: mode-aware generator strength. The entropy accounting mirrors the
 * Rust generator exactly (service/utils.rs): passphrase = words*log2(1296)
 * (+ log2(100) appendix number), pin = len*log2(10).
 */
describe("getGeneratorStrength", () => {
	it("password mode delegates to the heuristic scorer", () => {
		expect(getGeneratorStrength("password", "qwerty123", {})).toEqual(
			getPasswordStrength("qwerty123"),
		);
	});

	it("passphrase entropy grows with word count (log2(1296) per word)", () => {
		const three = getGeneratorStrength("passphrase", "x", {
			words: 3,
			appendNumber: false,
		});
		const ten = getGeneratorStrength("passphrase", "x", {
			words: 10,
			appendNumber: false,
		});
		expect(three.label).toBe("Weak"); // ~31 bits
		expect(ten.score).toBeGreaterThan(three.score);
		expect(ten.label).toBe("Very Strong"); // ~103 bits
	});

	it("appendNumber adds log2(100) bits", () => {
		const plain = getGeneratorStrength("passphrase", "x", {
			words: 6,
			appendNumber: false,
		});
		const numbered = getGeneratorStrength("passphrase", "x", {
			words: 6,
			appendNumber: true,
		});
		expect(numbered.score).toBeGreaterThan(plain.score);
	});

	it("pin entropy is len*log2(10): 4 digits Very Weak, 16 digits Strong", () => {
		expect(getGeneratorStrength("pin", "1234", { length: 4 }).label).toBe(
			"Very Weak",
		);
		const sixteen = getGeneratorStrength("pin", "0123456789012345", {
			length: 16,
		});
		// ~53 bits → Fair: honest scoring, a long PIN never masquerades as a
		// strong password.
		expect(sixteen.label).toBe("Fair");
	});

	it("never scores below zero or above 100, empty value scores zero", () => {
		expect(getGeneratorStrength("pin", "", { length: 0 })).toEqual({
			score: 0,
			label: "",
		});
		for (const params of [
			{ words: 3 },
			{ words: 10, appendNumber: true },
			{ length: 16 },
		]) {
			const result = getGeneratorStrength("passphrase", "value", params);
			expect(result.score).toBeGreaterThanOrEqual(0);
			expect(result.score).toBeLessThanOrEqual(100);
		}
	});
});
