// Password strength scoring shared with the desktop app.
//
// KEEP IN SYNC with src/utils/passwordStrength.ts — this file is a faithful
// port of that module (same weights, same penalties, same label tiers) so a
// given password always shows the SAME score and label in the popup and in
// the desktop UI. password-strength.test.js asserts the two-end agreement on
// representative passwords by re-implementing the TypeScript reference in
// the test; update both files together.

const COMMON_PASSWORDS = new Set([
	'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', 'master',
	'dragon', '111111', 'baseball', 'iloveyou', 'trustno1', 'sunshine',
	'princess', 'football', 'shadow', 'superman', 'michael', 'letmein',
	'password1', '123456789', '1234567890', 'admin', 'welcome', 'hello',
	'000000', 'charlie', 'donald', 'qwerty123', 'login', 'passw0rd',
]);

const SEQUENTIAL_PATTERNS = [
	'abcdefghijklmnopqrstuvwxyz',
	'zyxwvutsrqponmlkjihgfedcba',
	'01234567890',
	'09876543210',
];

/**
 * Score a password 0-100 and label it with the desktop's five tiers:
 * Very Weak (<=20) / Weak (<=40) / Fair (<=60) / Strong (<=80) / Very Strong.
 * Pure function, zero dependencies.
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
	// Common password
	if (COMMON_PASSWORDS.has(password.toLowerCase())) {
		score = 0;
	}

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

	// Only one character type
	if (variety === 1) score -= 15;

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
