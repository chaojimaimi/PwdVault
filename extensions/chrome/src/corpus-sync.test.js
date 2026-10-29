import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * v1.7.0 WP3 corpus-sync guard (fix_impl_plan_v1.7.0.md §5): the weak-password
 * corpus lives in three copies — the Rust source of truth
 * (crates/domain/src/weak_passwords.txt, one entry per line), the desktop
 * dense-string constant (src/utils/weakCorpus.ts) and the popup port
 * (weak-corpus.js, same dense-string carrying). This suite parses each copy
 * into a Set and pins them equal, so a corpus edit that misses a copy fails
 * here instead of silently diverging the three runtimes' weak verdicts.
 */

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..', '..');

const TXT_PATH = join(
	repoRoot,
	'src-tauri',
	'crates',
	'domain',
	'src',
	'weak_passwords.txt',
);
const TS_PATH = join(repoRoot, 'src', 'utils', 'weakCorpus.ts');
const JS_PATH = join(here, 'weak-corpus.js');

/** Rust-side parse parity with corpus.rs `corpus_set`: drop blanks and comments. */
function parseTxtCorpus(text) {
	const entries = text
		.split('\n')
		.map((line) => line.replace(/\r$/, ''))
		.filter((line) => line !== '' && !line.startsWith('#'));
	return new Set(entries);
}

/**
 * Extract the dense corpus literal from a TS/JS source file. The opening
 * quote is captured and backreferenced — deliberately quote-agnostic
 * (v1.4.1 lesson: the formatter may flip ' to "), the guard must survive
 * that. Appendix A guarantees the corpus itself contains no quote
 * characters, so the non-greedy stop is exact.
 */
function extractDenseCorpus(source, label) {
	const match = source.match(/CORPUS_DENSE\s*=\s*(['"`])([\s\S]*?)\1/);
	if (!match) {
		throw new Error(`CORPUS_DENSE dense literal not found in ${label}`);
	}
	return match[2];
}

/**
 * Extract the CORE_WORDS entries from a TS/JS source file: scan the array
 * literal between the declaration and its closing `]);` for quoted lowercase
 * tokens, with the same quote-agnostic backreference form. Line comments are
 * stripped first so prose can never contribute words.
 */
function extractCoreWords(source, label) {
	const start = source.indexOf('CORE_WORDS');
	if (start === -1) {
		throw new Error(`CORE_WORDS declaration not found in ${label}`);
	}
	const end = source.indexOf(']);', start);
	if (end === -1) {
		throw new Error(`CORE_WORDS array terminator not found in ${label}`);
	}
	const block = source
		.slice(start, end)
		.split('\n')
		.map((line) => line.replace(/\/\/.*$/, ''))
		.join('\n');
	const words = new Set();
	for (const match of block.matchAll(/(['"])([a-z0-9]+)\1/g)) {
		words.add(match[2]);
	}
	if (words.size === 0) {
		throw new Error(`CORE_WORDS extraction found no entries in ${label}`);
	}
	return words;
}

const txtCorpus = parseTxtCorpus(readFileSync(TXT_PATH, 'utf8'));
const tsCorpus = new Set(
	extractDenseCorpus(readFileSync(TS_PATH, 'utf8'), TS_PATH).split(' '),
);
const jsCorpus = new Set(
	extractDenseCorpus(readFileSync(JS_PATH, 'utf8'), JS_PATH).split(' '),
);

const tsCoreWords = extractCoreWords(readFileSync(TS_PATH, 'utf8'), TS_PATH);
const jsCoreWords = extractCoreWords(readFileSync(JS_PATH, 'utf8'), JS_PATH);

/** Appendix B sentinel carriers — must never join the core-word table. */
const EXCLUDED_CORE_WORDS = [
	'latest',
	'rocket',
	'quick',
	'brown',
	'correct',
	'horse',
	'battery',
	'staple',
	'troubador',
];

describe('three-end weak-password corpus sync (v1.7.0 WP3 guard)', () => {
	it('every copy parses to exactly 9952 entries', () => {
		expect(txtCorpus.size).toBe(9952);
		expect(tsCorpus.size).toBe(9952);
		expect(jsCorpus.size).toBe(9952);
	});

	it('the desktop dense constant matches the Rust txt entry for entry', () => {
		expect([...tsCorpus].sort()).toEqual([...txtCorpus].sort());
	});

	it('the popup dense constant matches the Rust txt entry for entry', () => {
		expect([...jsCorpus].sort()).toEqual([...txtCorpus].sort());
	});

	it('the famous-forms exact anchor p@ssw0rd123 exists in all three copies', () => {
		// The P@ssw0rd123 must-weak vector rides corpus EXACT (normalization
		// welds the trailing 3 into "password12e") — a copy dropping this
		// anchor would silently flip that classification on its runtime.
		for (const [label, corpus] of [
			['rust txt', txtCorpus],
			['weakCorpus.ts', tsCorpus],
			['weak-corpus.js', jsCorpus],
		]) {
			expect(corpus.has('p@ssw0rd123'), label).toBe(true);
		}
	});
});

describe('core-word table sync (Appendix B guard)', () => {
	it('weakCorpus.ts and weak-corpus.js carry the same 72 core words', () => {
		// 72 is the frozen cardinality (corpus.rs's CORE_WORDS: [&str; 72]);
		// adding or removing a word is a three-end Appendix B change.
		expect(tsCoreWords.size).toBe(72);
		expect([...jsCoreWords].sort()).toEqual([...tsCoreWords].sort());
	});

	it.each(EXCLUDED_CORE_WORDS)('excluded word %s never joins either table', (word) => {
		expect(tsCoreWords.has(word)).toBe(false);
		expect(jsCoreWords.has(word)).toBe(false);
	});
});
