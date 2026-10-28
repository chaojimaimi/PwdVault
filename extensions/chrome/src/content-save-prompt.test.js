import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

// v1.6.0 save/update prompt contract. The content script is a set of six
// classic files (joined in manifest order for the v1.6.3 split — count
// assertions keep their union semantics on the joined text) and background.js
// a service worker with top-level chrome.* listeners, so (like
// content-is-trusted.test.js / background-fill-gate.test.js) these are
// source-text contracts: the guard ordering, the digest-only CHECK boundary,
// the single plaintext disclosure point, and the old-desktop degradation are
// all pinned on the source so a refactor cannot silently drop them.
// background-side assertions read background-commands.js — the v1.6.3 split
// moved the whole save-prompt handler cluster (incl. verifyUnsupported)
// there.
const here = dirname(fileURLToPath(import.meta.url));
const CONTENT_FILES = [
	'domain-match.js',
	'content-forms.js',
	'content-ui-shadow.js',
	'content-ui-bar.js',
	'content-save-prompt.js',
	'content.js',
];
const content = CONTENT_FILES.map((name) =>
	readFileSync(join(here, name), 'utf8'),
).join('\n');
const background = readFileSync(join(here, 'background-commands.js'), 'utf8');

const GUARD = 'if (!e.isTrusted) return;';

// Balanced-brace body extraction (same approach as background-fill-gate).
function functionBody(source, name) {
  let start = source.indexOf(`async function ${name}(`);
  if (start < 0) start = source.indexOf(`function ${name}(`);
  expect(start, `${name} found`).toBeGreaterThanOrEqual(0);
  const bodyStart = source.indexOf('{', start);
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

// The three submit-capture listeners: [label, start anchor, end anchor].
const CAPTURE_PATHS = [
  ['form submit event', '// Path 1 - the form submit event', '// Path 2 - a click on a plausible'],
  ['submit-button click', '// Path 2 - a click on a plausible', '// Path 3 - Enter pressed in a password box'],
  ['password Enter', '// Path 3 - Enter pressed in a password box', '// Message Handling'],
];

describe('save prompt: three trusted capture paths', () => {
  for (const [label, startAnchor, endAnchor] of CAPTURE_PATHS) {
    it(`${label}: the isTrusted guard precedes the capture hand-off`, () => {
      const start = content.indexOf(startAnchor);
      expect(start, `start anchor not found: ${startAnchor}`).toBeGreaterThanOrEqual(0);
      const end = content.indexOf(endAnchor, start + startAnchor.length);
      expect(end, `end anchor not found: ${endAnchor}`).toBeGreaterThan(start);

      const segment = content.slice(start, end);
      const guardAt = segment.indexOf(GUARD);
      const callAt = segment.indexOf('handlePossibleSubmit(');
      expect(guardAt, `missing guard in ${label}`).toBeGreaterThanOrEqual(0);
      expect(callAt, `missing capture call in ${label}`).toBeGreaterThanOrEqual(0);
      expect(guardAt, `guard must come before the capture in ${label}`).toBeLessThan(callAt);
    });
  }

  it('the shared sink reads field values only after the secure-context gate', () => {
    const body = functionBody(content, 'handlePossibleSubmit');
    const detectAt = body.indexOf('crypto?.subtle');
    const valueAt = body.indexOf('.value');
    expect(detectAt).toBeGreaterThanOrEqual(0);
    expect(valueAt).toBeGreaterThanOrEqual(0);
    // No plaintext is read (let alone digested or sent) on a plain-http page.
    expect(detectAt).toBeLessThan(valueAt);
  });
});

describe('save prompt: digest-only CHECK boundary', () => {
  it('computes the digest only after the crypto.subtle feature-detect', () => {
    const sectionStart = content.indexOf('Save/Update Prompt (v1.6.0)');
    const sectionEnd = content.indexOf('// Message Handling', sectionStart);
    const section = content.slice(sectionStart, sectionEnd);
    const detectAt = section.indexOf('crypto?.subtle');
    const digestAt = section.indexOf('digestText(');
    expect(detectAt).toBeGreaterThanOrEqual(0);
    expect(digestAt).toBeGreaterThanOrEqual(0);
    expect(detectAt, 'feature-detect must precede digest computation').toBeLessThan(digestAt);
  });

  it('the CHECK message carries a digest and candidate triples, never a password', () => {
    const checkBody = functionBody(content, 'checkSaveDecision');
    expect(checkBody).toContain('CHECK_SAVE_CREDENTIALS');
    // Formatter-tolerant (the call may wrap across lines): the digest is
    // computed through the namespace digestText, never inline.
    expect(checkBody).toMatch(
      /password_sha256:\s*await\s+globalThis\.PwdVaultContent\.digestText\(\s*password,?\s*\)/,
    );
    expect(checkBody).toContain('id: entry.id');
    expect(checkBody, 'no plaintext field on the CHECK message').not.toContain('password:');
  });

  it('background checkSaveCredentials holds no plaintext (digest + ids/titles only)', () => {
    const body = functionBody(background, 'checkSaveCredentials');
    // Strip the digest-carrying tokens, then demand the plaintext name is gone.
    const sanitized = body
      .replaceAll('password_sha256', 'digest')
      .replaceAll('passwordSha256', 'digest');
    expect(sanitized).not.toContain('password');
    expect(body).toContain('verifyEntryPassword(');
    // Degraded/empty/no-match outcomes answer "none"; quote-agnostic because
    // the repo formatter flips quote styles freely (v1.5.0 lesson).
    expect(body).toMatch(/action: (['"])none\1/);
  });

  it('background verify rides the id_param channel of verify_entry_password', () => {
    const body = functionBody(background, 'verifyEntryPassword');
    expect(body).toContain('verify_entry_password');
    expect(body).toContain('id_param: id');
    expect(body).toContain('password_sha256: passwordSha256');
    expect(body).toContain('result.matches');
  });

  it('the plaintext password enters a message at exactly one construction site', () => {
    // buildSavePayload is the ONLY place creds.password is copied into an
    // outbound message (the SAVE_LOGIN_CONFIRMED confirm send).
    expect(content.split('password: creds.password').length - 1).toBe(1);
    const payloadBody = functionBody(content, 'buildSavePayload');
    expect(payloadBody).toContain('SAVE_LOGIN_CONFIRMED');
    expect(payloadBody).toMatch(/mode: (['"])create\1/);
    expect(payloadBody).toMatch(/mode: (['"])update\1/);
  });
});

describe('save prompt: page-side confirm bar', () => {
  it('mounts through the single mountShadowHost choke point with a 60s self-destruct', () => {
    const body = functionBody(content, 'presentSavePrompt');
    expect(body).toContain('mountShadowHost(');
    expect(body).toContain('60000');
  });

  it('keeps at most one pending prompt (in-flight single-instance pattern)', () => {
    expect(content).toContain('let pendingSaveBar');
    expect(content).toContain('function dismissSavePrompt');
    const body = functionBody(content, 'presentSavePrompt');
    // The previous prompt is dismissed BEFORE the new host is mounted.
    expect(body.indexOf('dismissSavePrompt()')).toBeLessThan(body.indexOf('mountShadowHost('));
  });

  it('drops the captured plaintext on every exit path', () => {
    const body = functionBody(content, 'presentSavePrompt');
    // Confirm, dismiss, and the 60s timer each drop the plaintext before/at
    // closing the bar.
    expect(body.split('dropPlaintext()').length - 1).toBeGreaterThanOrEqual(3);
    expect(body).toContain('creds.password = ""');
  });

  it('a locked vault tears down any pending prompt', () => {
    const lockAt = content.indexOf('case "VAULT_LOCKED":');
    expect(lockAt).toBeGreaterThanOrEqual(0);
    const arm = content.slice(lockAt, lockAt + 500);
    expect(arm).toContain('dismissSavePrompt()');
  });
});

describe('save prompt: old-desktop degradation', () => {
  it('disables silently for the session on an unknown-command error', () => {
    const body = functionBody(background, 'checkSaveCredentials');
    expect(body).toContain('isUnknownCommandError(');
    expect(body).toContain('verifyUnsupported = true');
    // Degradation answers "none" (no prompt), never an error.
    expect(body).toContain('verifyUnsupported');
  });

  it('the degradation flag is module-level session state', () => {
    expect(background).toContain('let verifyUnsupported = false;');
    const unknown = functionBody(background, 'isUnknownCommandError');
    expect(unknown).toContain('unknown command');
  });
});
