import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

// background.js is a service worker with top-level chrome.* listeners and no
// exports, so (like the content.js guards) this is a source-text contract:
// the auto-fill list builder must delegate to the STRICT sender gate.
//
// Why the STRICT gate and not entryMatchesPageUrl: the strict gate rejects
// an empty entry.url, so generic entries (no stored URL) can never appear in
// an auto-fill list — every getEntriesForUrl consumer relies on that
// invariant ("non-empty URL, fail closed"). The wide gate would let a
// generic entry fill on ANY page.

const here = dirname(fileURLToPath(import.meta.url));
const background = readFileSync(join(here, 'background.js'), 'utf8');
const senderAuth = readFileSync(join(here, 'sender-auth.js'), 'utf8');

function functionBody(source, name) {
  const start = source.indexOf(`async function ${name}(`);
  expect(start, `${name} found in background.js`).toBeGreaterThanOrEqual(0);
  const bodyStart = source.indexOf('{', start);
  // Balanced-brace scan — robust regardless of indentation/nesting.
  let depth = 0;
  for (let i = bodyStart; i < source.length; i += 1) {
    if (source[i] === '{') depth += 1;
    if (source[i] === '}') {
      depth -= 1;
      if (depth === 0) return source.slice(bodyStart, i + 1);
    }
  }
  throw new Error(`unbalanced braces in ${name}`);
}

describe('background auto-fill list gate (v1.4.0)', () => {
  it('getEntriesForUrl delegates to the strict entryMatchesSenderUrl gate', () => {
    expect(background).toContain(
      'import { authorizeMessage, entryMatchesSenderUrl } from "./sender-auth.js"',
    );
    const body = functionBody(background, 'getEntriesForUrl');
    expect(body).toContain('entryMatchesSenderUrl(entry, url)');
  });

  it('no third hand-rolled hostname comparison remains in getEntriesForUrl', () => {
    const body = functionBody(background, 'getEntriesForUrl');
    // The v1.3.x implementation compared stripped hostnames inline; the
    // eTLD+1 semantics live in sender-auth.js alone now.
    expect(body).not.toContain('hostname.replace');
    expect(body).not.toContain('new URL(entry.url)');
  });

  it('the strict gate rejects generic entries (empty entry.url)', () => {
    // The invariant the delegation above depends on, re-asserted against the
    // live predicate: an entry without a URL never matches any sender URL.
    expect(senderAuth).toContain('!senderDomain || !rawEntryUrl) return false');
    // Quote-agnostic via backreference: the invariant under test is semantic,
    // not the quote style (the repo-wide formatter pass flips quotes freely).
    expect(senderAuth).toMatch(
      /const rawEntryUrl = typeof entry\?\.url === (['"])string\1 \? entry\.url : \1\1;/,
    );
  });
});

describe('generator mode passthrough (v1.4.0)', () => {
	it('generatePassword forwards the mode and passphrase fields to the app', () => {
		const start = background.indexOf('async function generatePassword(');
		expect(start).toBeGreaterThanOrEqual(0);
		const body = background.slice(start, start + 1200);
		// The dispatcher contract (#[serde(default)] GeneratorOptions.mode)
		// only pays off if the background actually relays the new fields.
		expect(body).toContain('options.mode');
		expect(body).toContain('generatorOptions.mode = options.mode');
		expect(body).toContain('generatorOptions.words = options.words');
		expect(body).toContain('generatorOptions.separator = options.separator');
		expect(body).toContain('generatorOptions.append_number = options.appendNumber');
	});

	it('the popup generator screen sends a mode with every generate call', () => {
		const popup = readFileSync(join(here, 'popup', 'popup.js'), 'utf8');
		expect(popup).toContain('generatorMode');
		const genStart = popup.indexOf('async handleGenerate()');
		expect(genStart).toBeGreaterThanOrEqual(0);
		const genBody = popup.slice(genStart, genStart + 900);
		expect(genBody).toMatch(/mode:\s*mode|mode,\s*\.\.\./);
	});
});
