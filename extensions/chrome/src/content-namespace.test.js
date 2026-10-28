import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

// v1.6.3 WP1 namespace contract. content.js was split into six classic
// content scripts loaded (in manifest order) into one isolated world.
// domain-match.js is byte-frozen and its top-level declarations are the ONLY
// cross-file bare identifiers; every other cross-file function and mutable
// state must travel through the globalThis.PwdVaultContent namespace using
// FULL-NAME references and mounts (no NS alias, no /* global */ comment).
// This test statically cross-checks the six sources so a dangling reference
// fails here instead of as a runtime TypeError on real pages, and it refuses
// vacuous passes: an empty reference set, an empty frozen set, or an eslint
// globals list that drifted from the frozen set are all hard failures.
const here = dirname(fileURLToPath(import.meta.url));

// Must equal the content_scripts.js arrays in BOTH manifests (load order).
const CONTENT_FILES = [
	'domain-match.js',
	'content-forms.js',
	'content-ui-shadow.js',
	'content-ui-bar.js',
	'content-save-prompt.js',
	'content.js',
];

// The frozen domain-match declarations (byte-identical with sender-auth.js;
// declared at top level of a classic script, shared through the isolated
// world's global scope).
const FROZEN_NAMES = [
	'MULTI_LABEL_SUFFIXES',
	'registeredDomain',
	'normalizedDomain',
	'entryMatchMode',
	'exactHost',
	'entryMatchesSenderUrl',
	'entryMatchesPageUrl',
];

const sources = new Map(
	CONTENT_FILES.map((name) => [name, readFileSync(join(here, name), 'utf8')]),
);
const joined = CONTENT_FILES.map((name) => sources.get(name)).join('\n');

// Every namespace touch must spell the property out in full.
const refPattern = /globalThis\.PwdVaultContent\.([A-Za-z_$][\w$]*)/g;
// Mounts/state writes: an assignment right after the full property name.
const defPattern = /globalThis\.PwdVaultContent\.([A-Za-z_$][\w$]*)\s*=/g;
const refs = [...joined.matchAll(refPattern)].map((match) => match[1]);
const defs = new Set([...joined.matchAll(defPattern)].map((match) => match[1]));

describe('content split namespace contract (v1.6.3)', () => {
	it('keeps a non-empty reference set and mounts every referenced property', () => {
		// Vacuous-pass guard: the split must actually use the namespace.
		expect(refs.length).toBeGreaterThanOrEqual(8);
		const uniqueRefs = [...new Set(refs)];
		for (const name of uniqueRefs) {
			expect(
				defs.has(name),
				`no full-name mount for PwdVaultContent.${name}`,
			).toBe(true);
		}
	});

	it('initializes the namespace idempotently in every IIFE file', () => {
		for (const name of CONTENT_FILES.slice(1)) {
			expect(
				sources.get(name).includes('globalThis.PwdVaultContent ??= {};'),
				`${name} is missing the namespace init line`,
			).toBe(true);
		}
	});

	it('bans /* global */ comments in the content files', () => {
		// A /* global */ comment would silently neuter the no-undef gate that
		// makes bare references to unmounted names fail lint.
		expect(joined).not.toContain('/* global');
	});

	it('domain-match.js declares exactly the frozen set at top level', () => {
		const decls = [
			...sources
				.get('domain-match.js')
				.matchAll(/^(?:const|function) ([A-Za-z_$][\w$]*)/gm),
		].map((match) => match[1]);
		// Empty set = the frozen block is gone → hard failure.
		expect(decls.length).toBeGreaterThan(0);
		expect([...new Set(decls)].sort()).toEqual([...FROZEN_NAMES].sort());
	});

	it('the eslint no-undef globals list matches the frozen set exactly', () => {
		const config = readFileSync(
			join(here, '../../../eslint.config.js'),
			'utf8',
		);
		const declared = [
			...config.matchAll(/([A-Za-z_$][\w$]*):\s*"readonly"/g),
		].map((match) => match[1]);
		// The only other "readonly" globals are the extension-API block
		// (chrome/browser/window/document) shared by every extension source.
		expect([...new Set(declared)].sort()).toEqual(
			[...FROZEN_NAMES, 'chrome', 'browser', 'window', 'document'].sort(),
		);
	});

	it('both manifests load the six files in the contract order', () => {
		const expected = CONTENT_FILES.map((name) => `src/${name}`);
		const chrome = JSON.parse(
			readFileSync(join(here, '../manifest.json'), 'utf8'),
		);
		const firefox = JSON.parse(
			readFileSync(join(here, '../../firefox/manifest.json'), 'utf8'),
		);
		expect(chrome.content_scripts[0].js).toEqual(expected);
		expect(firefox.content_scripts[0].js).toEqual(expected);
	});
});
