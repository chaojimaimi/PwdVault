import { describe, expect, it } from 'vitest';
import {
	getGeneratorStrength as popupGeneratorStrength,
	getPasswordStrength as popupStrength,
	KEYBOARD_WALK_PATTERNS as popupWalkPatterns,
} from './password-strength.js';
import {
	coreWordFormulaHit as popupFormulaHit,
	corpusExactHit as popupExactHit,
	corpusNormalizedHit as popupNormalizedHit,
} from './weak-corpus.js';
// The TypeScript reference implementations used by the desktop UI. Importing
// them directly (vite transforms TS in tests) makes this a true two-end parity
// test: any drift between the popup port and the desktop module fails here.
import {
	getGeneratorStrength as desktopGeneratorStrength,
	getPasswordStrength as desktopStrength,
	KEYBOARD_WALK_PATTERNS as desktopWalkPatterns,
} from '../../../src/utils/passwordStrength';
import {
	coreWordFormulaHit as desktopFormulaHit,
	corpusExactHit as desktopExactHit,
	corpusNormalizedHit as desktopNormalizedHit,
} from '../../../src/utils/weakCorpus';

// The classification-vector blocks below mirror the desktop-side
// src/utils/__tests__/passwordClassification.test.ts (v1.7.0 Appendix B,
// frozen after the WP1 zxcvbn measurements): the must-weak set asserts
// score <= 40 on BOTH ends, the sentinels assert none of the new penalties
// fire on either end, and "Test@1qaz" pins the exact 38 that the
// keyboard-walk arithmetic produces. Keep the two vector tables aligned.

describe('popup password strength parity with the desktop', () => {
	const cases = [
		'', // empty
		'password', // corpus exact hit → clamped to 10
		'123456', // corpus exact + sequence
		'abc', // short single-type
		'abcdefgh', // sequential run
		'aaaaaaaaaaa', // repetition
		'qwerty123', // corpus + keyboard walk (qwer/wert/erty)
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
		// v1.7.0: "sunshine2026" became a core-word-formula hit (sunshine at
		// the string start with a digit-only tail), so the corpus clamp makes
		// it Very Weak — the old "Fair" example doubles as a regression pin.
		expect(labelOf('sunshine2026')).toBe('Very Weak');
		expect(labelOf('quartz67vxm')).toBe('Fair');
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

/** Distinct keyboard-walk windows present in the raw lowercase password. */
const walkHits = (password, patterns) =>
	patterns.filter((pattern) => password.toLowerCase().includes(pattern));

/** [password, expected mechanism — kept aligned with corpus.rs's notes]. */
const MUST_WEAK = [
	['password1!', 'core-word formula (raw form)'],
	['admin123', 'corpus exact + core-word formula'],
	['Admin@123', 'core-word formula (raw form)'],
	['Test@12#$', 'core-word formula (raw form)'],
	['Test@1qaz', 'keyboard walk: qaz + 1qaz, 2 hits x -15 (68 - 30 = 38)'],
	['P@ssw0rd123', 'corpus exact (famous-forms anchor)'],
	['1qaz2wsx', 'corpus exact + keyboard walk'],
	['woaini520', 'corpus exact (Chinese supplement)'],
	['qq123456', 'corpus exact'],
	['a123456', 'corpus exact'],
	['sunshine123', 'core-word formula'],
	['qwerty!@#', 'core-word formula'],
];

describe('v1.7.0 weak-classification vectors (Appendix B, both ends)', () => {
	it('carries the same keyboard-walk table as the desktop', () => {
		expect(popupWalkPatterns).toEqual(desktopWalkPatterns);
	});

	it.each(MUST_WEAK)('%s lands weak on both ends via %s', (password) => {
		expect(popupStrength(password).score).toBeLessThanOrEqual(40);
		expect(desktopStrength(password).score).toBeLessThanOrEqual(40);
	});

	it('Test@1qaz misses the corpus and rides the walk penalty to exactly 38', () => {
		// Mechanism pin: the walk is load-bearing here, so the corpus checks
		// MUST stay silent on both ends (a future corpus edit adding
		// "test@1qaz" would hide the walk arithmetic this vector freezes).
		for (const [exact, normalized, formula] of [
			[popupExactHit, popupNormalizedHit, popupFormulaHit],
			[desktopExactHit, desktopNormalizedHit, desktopFormulaHit],
		]) {
			expect(exact('Test@1qaz')).toBe(false);
			expect(normalized('Test@1qaz')).toBe(false);
			expect(formula('Test@1qaz')).toBe(false);
		}
		expect(walkHits('Test@1qaz', popupWalkPatterns)).toEqual(['qaz', '1qaz']);
		expect(popupStrength('Test@1qaz').score).toBe(38);
		expect(desktopStrength('Test@1qaz').score).toBe(38);
	});
});

/** Appendix B false-positive sentinels — none may trip a new penalty. */
const SENTINELS = [
	'kX9$mP2!vL5#nQ8@wR4&jF7^',
	'correcthorsebatterystaple',
	'D7g!kLm9@pQ2',
	'latest#Rocket9',
	'7hE-qu1ck-b0wnes',
];

describe('false-positive sentinels (Appendix B, both ends)', () => {
	it.each(SENTINELS)(
		'%s trips none of the new penalties on either end',
		(password) => {
			for (const [exact, normalized, formula, patterns] of [
				[popupExactHit, popupNormalizedHit, popupFormulaHit, popupWalkPatterns],
				[
					desktopExactHit,
					desktopNormalizedHit,
					desktopFormulaHit,
					desktopWalkPatterns,
				],
			]) {
				expect(exact(password)).toBe(false);
				expect(normalized(password)).toBe(false);
				expect(formula(password)).toBe(false);
				expect(walkHits(password, patterns)).toEqual([]);
			}
		},
	);
});

describe('popup generator strength parity with the desktop (v1.4.0)', () => {
	const passphraseCases = [
		{ words: 3, appendNumber: false },
		{ words: 5, appendNumber: true },
		{ words: 10, appendNumber: false },
	];
	const pinCases = [4, 6, 12, 16];

	it.each(passphraseCases.map((p) => [JSON.stringify(p), p]))(
		'passphrase %j agrees with the desktop',
		(_label, params) => {
			expect(popupGeneratorStrength('passphrase', 'word-word', params)).toEqual(
				desktopGeneratorStrength('passphrase', 'word-word', params),
			);
		},
	);

	it.each(pinCases.map((n) => [n, { length: n }]))(
		'pin length %j agrees with the desktop',
		(len, params) => {
			expect(popupGeneratorStrength('pin', '1234', params)).toEqual(
				desktopGeneratorStrength('pin', '1234', params),
			);
		},
	);

	it('password mode delegates to the shared heuristic scorer', () => {
		expect(popupGeneratorStrength('password', 'qwerty123', {})).toEqual(
			popupStrength('qwerty123'),
		);
		expect(desktopGeneratorStrength('password', 'qwerty123', {})).toEqual(
			desktopStrength('qwerty123'),
		);
	});

	it('entropy accounting matches the Rust generator contract', () => {
		// 5 words = 5*log2(1296) ≈ 51.7 bits → Fair; 6 words ≈ 62 bits →
		// Strong; a 4-digit PIN (≈13.3 bits) is Very Weak.
		const fiveWords = popupGeneratorStrength('passphrase', 'x', {
			words: 5,
			appendNumber: false,
		});
		expect(fiveWords.label).toBe('Fair');
		const sixWords = popupGeneratorStrength('passphrase', 'x', {
			words: 6,
			appendNumber: false,
		});
		expect(sixWords.label).toBe('Strong');
		const sixWordsPlus = popupGeneratorStrength('passphrase', 'x', {
			words: 6,
			appendNumber: true,
		});
		expect(sixWordsPlus.score).toBeGreaterThan(sixWords.score);
		expect(
			popupGeneratorStrength('pin', '1234', { length: 4 }).label,
		).toBe('Very Weak');
	});
});
