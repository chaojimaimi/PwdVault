import { describe, expect, it } from 'vitest';
import { getPasswordStrength as popupStrength } from './password-strength.js';
// The TypeScript reference implementation used by the desktop UI. Importing
// it directly (vite transforms TS in tests) makes this a true two-end parity
// test: any drift between the popup port and the desktop module fails here.
import { getPasswordStrength as desktopStrength } from '../../../src/utils/passwordStrength';

describe('popup password strength parity with the desktop', () => {
	const cases = [
		'', // empty
		'password', // common password → score clamped to 0
		'123456', // common + sequence
		'abc', // short single-type
		'abcdefgh', // sequential run
		'aaaaaaaaaaa', // repetition
		'qwerty123', // common + sequence
		'CorrectHorseBatteryStaple',
		'Tr0ub4dor&3x',
		'xK9$mQ2#vL8pW4nZ',
		'p@ssw0rd!ExtraLong2026',
	];

	it.each(cases)('agrees with the desktop on %j', (password) => {
		expect(popupStrength(password)).toEqual(desktopStrength(password));
	});

	it('labels map to the desktop five tiers', () => {
		const labelOf = (pw) => popupStrength(pw).label;
		expect(labelOf('password')).toBe('Very Weak');
		expect(labelOf('fairg34')).toBe('Weak');
		expect(labelOf('sunshine2026')).toBe('Fair');
		expect(labelOf('xK9$mQ2#vL8pW4nZ')).toBe('Strong');
		// Note: with the shared scoring caps (30 length + 30 variety + 15
		// uniqueness) the maximum reachable score is 75, so the fifth tier
		// "Very Strong" (>80) is currently unreachable on BOTH ends — the
		// parity guarantee is what this suite pins down.
		expect(labelOf('xK9$mQ2#vL8pW4nZ7BeqT')).toBe('Strong');
	});

	it('never scores below zero or above 100', () => {
		for (const pw of ['password', 'zzzz', 'aB3!aB3!aB3!aB3!aB3!aB3!']) {
			const { score } = popupStrength(pw);
			expect(score).toBeGreaterThanOrEqual(0);
			expect(score).toBeLessThanOrEqual(100);
		}
	});
});
