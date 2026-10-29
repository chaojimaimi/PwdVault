// Password strength scoring shared with the desktop app.
//
// KEEP IN SYNC with src/utils/passwordStrength.ts — this file is a verbatim
// port of that module (same weights, same penalties, same label tiers) so a
// given password always shows the SAME score and label in the popup and in
// the desktop UI. v1.7.0: the old 31-entry common-password zeroing is
// replaced by the shared weak-password corpus layer (weak-corpus.js — exact /
// vowel-normalized / core-word-formula lookups ported from the Rust
// corpus.rs; any hit clamps the score to 10) plus a keyboard-walk penalty
// (-15 per distinct window). password-strength.test.js asserts two-end
// agreement; corpus-sync.test.js pins the corpus copies equal. Update all
// three files together.
import {
	coreWordFormulaHit,
	corpusExactHit,
	corpusNormalizedHit,
} from './weak-corpus.js';

/**
 * Keyboard-walk windows (v1.7.0 Appendix B three-end constant): horizontal
 * rows, vertical columns and the digit-column prefixes. Matched as raw
 * substrings of the lowercased password — walk detection deliberately does
 * NOT go through the leet normalization ("1qaz" is in the table as-is). The
 * desktop copy mirrors this table; the classification vector tests pin
 * both sides. (The plan header says "28" but enumerates these 30 distinct
 * windows — the enumeration is normative: e.g. "Test@1qaz" needs BOTH "qaz"
 * and "1qaz" to land at 38.)
 */
export const KEYBOARD_WALK_PATTERNS = [
	'qwer', 'wert', 'erty', 'rtyu', 'tyui', 'yuio', 'uiop',
	'asdf', 'sdfg', 'dfgh', 'fghj', 'ghjk', 'hjkl',
	'zxcv', 'xcvb', 'cvbn',
	'qaz', 'wsx', 'edc', 'rfv', 'tgb', 'yhn', 'ujm', 'ikl',
	'1qaz', '2wsx', '3edc', '4rfv', '5tgb', '6yhn',
];

const SEQUENTIAL_PATTERNS = [
	'abcdefghijklmnopqrstuvwxyz',
	'zyxwvutsrqponmlkjihgfedcba',
	'01234567890',
	'09876543210',
];

/**
 * Score a password 0-100 and label it with the desktop's five tiers:
 * Very Weak (<=20) / Weak (<=40) / Fair (<=60) / Strong (<=80) / Very Strong.
 * Pure function, zero dependencies beyond the corpus layer.
 *
 * @param {string} password
 * @returns {{ score: number, label: string }}
 */
export function getPasswordStrength(password) {
	if (!password) return { score: 0, label: '' };

	let score = 0;

	// Length scoring (up to 30 points)
	score += Math.min(30, password.length * 2.5);

	// Character variety (up to 30 points)
	const hasLower = /[a-z]/.test(password);
	const hasUpper = /[A-Z]/.test(password);
	const hasNumbers = /\d/.test(password);
	const hasSymbols = /[^a-zA-Z\d]/.test(password);

	const variety = [hasLower, hasUpper, hasNumbers, hasSymbols].filter(Boolean).length;
	score += variety * 7.5;

	// Entropy bonus for mixed character types (up to 15 points)
	if (password.length >= 8) {
		const uniqueChars = new Set(password).size;
		score += Math.min(15, (uniqueChars / password.length) * 15);
	}

	// Penalties
	// Repeated characters
	const repeatedChars = (password.match(/(.)\1{2,}/g) || []).length;
	score -= repeatedChars * 10;

	// Sequential characters
	const lower = password.toLowerCase();
	for (const pattern of SEQUENTIAL_PATTERNS) {
		for (let i = 0; i <= pattern.length - 4; i++) {
			if (lower.includes(pattern.substring(i, i + 4))) {
				score -= 10;
			}
		}
	}

	// Keyboard walks (v1.7.0): each DISTINCT window found as a substring of
	// the raw lowercase password costs 15 — -15 (not -10) so "Test@1qaz"
	// (qaz + 1qaz, 2 hits) lands at 38, inside the weak band.
	let walkHits = 0;
	for (const pattern of KEYBOARD_WALK_PATTERNS) {
		if (lower.includes(pattern)) {
			walkHits += 1;
		}
	}
	score -= walkHits * 15;

	// Only one character type
	if (variety === 1) score -= 15;

	// Weak-password corpus layer (v1.7.0): any of the three lookups hitting
	// clamps the score into the Very Weak band — replaces the old 31-entry
	// common-password zeroing. The clamp sits AFTER the penalties so it caps
	// the final score ("password" → 10) without shielding a hit from them.
	if (
		corpusExactHit(password) ||
		corpusNormalizedHit(password) ||
		coreWordFormulaHit(password)
	) {
		score = Math.min(score, 10);
	}

	// Clamp
	score = Math.max(0, Math.min(100, Math.round(score)));

	// Determine label (color is owned by the theme; the popup maps the label
	// to its color variables exactly like the desktop's strength-* CSS).
	let label;
	if (score <= 20) {
		label = 'Very Weak';
	} else if (score <= 40) {
		label = 'Weak';
	} else if (score <= 60) {
		label = 'Fair';
	} else if (score <= 80) {
		label = 'Strong';
	} else {
		label = 'Very Strong';
	}

	return { score, label };
}

/**
 * Mode-aware generator strength (v1.4.0) — byte-parity port of
 * src/utils/passwordStrength.ts `getGeneratorStrength` (the desktop is the
 * source of truth; the parity test pins both entry points).
 *
 * Charset passwords go through the heuristic scorer above; passphrase and
 * PIN entropy is computed from the PARAMETERS exactly like the Rust
 * generator: passphrase = words*log2(1296) (+ log2(100) with the appendix
 * number), pin = len*log2(10).
 */
export function getGeneratorStrength(
	mode,
	value,
	params = {},
) {
	if (mode === 'password') return getPasswordStrength(value);
	if (!value) return { score: 0, label: '' };

	let bits;
	if (mode === 'passphrase') {
		const words = Math.max(0, params.words ?? 0);
		bits = words * Math.log2(1296) + (params.appendNumber ? Math.log2(100) : 0);
	} else {
		bits = Math.max(0, params.length ?? 0) * Math.log2(10);
	}

	// Piecewise anchors (bits → score): linear between points.
	const anchors = [
		[0, 0],
		[28, 20],
		[45, 40],
		[60, 60],
		[80, 80],
		[110, 100],
	];
	let score = 100;
	for (let i = 1; i < anchors.length; i += 1) {
		const [hiBits, hiScore] = anchors[i];
		if (bits <= hiBits) {
			const [loBits, loScore] = anchors[i - 1];
			score =
				loScore + ((bits - loBits) / (hiBits - loBits)) * (hiScore - loScore);
			break;
		}
	}
	score = Math.max(0, Math.min(100, Math.round(score)));

	let label;
	if (score <= 20) {
		label = 'Very Weak';
	} else if (score <= 40) {
		label = 'Weak';
	} else if (score <= 60) {
		label = 'Fair';
	} else if (score <= 80) {
		label = 'Strong';
	} else {
		label = 'Very Strong';
	}

	return { score, label };
}
