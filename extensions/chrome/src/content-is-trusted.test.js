import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

// The content script is a set of six classic files loaded IN ORDER into one
// isolated world (the manifest content_scripts.js array), so like the
// sender-auth verbatim guard this test asserts on the source text: every
// handler that can pull plaintext credentials must begin with the isTrusted
// gate, before any secret-fetching call. jsdom cannot run these handlers
// (isTrusted is always false there), so the source contract is what keeps a
// synthetic-event refactor from silently dropping the gate.
//
// v1.6.3 split: the counts are UNION semantics — the six files are joined in
// manifest order and asserted as one text. Never split the numbers or assert
// per-file: a new secret-touching handler in ANY of the six files must be
// globally visible to this guard.
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

const GUARD = 'if (!e.isTrusted) return;';

// Each site: [label, segment start anchor, end anchor, first secret access]
const GUARDED_SITES = [
  [
    '#pv-fill click (auto-fill bar)',
    '.querySelector("#pv-fill")',
    '.querySelector("#pv-dismiss")',
    'chrome.runtime.sendMessage',
  ],
  [
    'overlay item click (selectEntry)',
    '// Click to fill',
    '// Copy button',
    'selectEntry(',
  ],
  [
    'overlay copy button (copyEntryPassword)',
    '// Copy button',
    'list.appendChild(item);',
    'copyEntryPassword(',
  ],
  [
    'Ctrl+Shift+L keydown (showOverlay)',
    'document.addEventListener("keydown", (e) => {',
    'Message Handling',
    'showOverlay(',
  ],
  // v1.6.0 save/update prompt: three submit-capture paths converge on
  // handlePossibleSubmit (which reads the field .value plaintexts) and the
  // confirm click builds the SAVE_LOGIN_CONFIRMED payload.
  [
    'form submit capture (save prompt)',
    '// Path 1 - the form submit event',
    '// Path 2 - a click on a plausible',
    'handlePossibleSubmit(',
  ],
  [
    'submit-button click capture (save prompt)',
    '// Path 2 - a click on a plausible',
    '// Path 3 - Enter pressed in a password box',
    'handlePossibleSubmit(',
  ],
  [
    'password Enter capture (save prompt)',
    '// Path 3 - Enter pressed in a password box',
    '// Message Handling',
    'handlePossibleSubmit(',
  ],
  [
    'save/update confirm click (SAVE_LOGIN_CONFIRMED)',
    'The only path where the captured plaintext',
    'const dismissHandler = () => {',
    'buildSavePayload(',
  ],
];

describe('content.js isTrusted source guard', () => {
  it('carries exactly the eight credential-triggering guards', () => {
    // Exact count: a new secret-touching handler must add its guard AND
    // register it here — silent additions fail this assertion.
    expect(content.split(GUARD).length - 1).toBe(8);
  });

  for (const [label, startAnchor, endAnchor, secretCall] of GUARDED_SITES) {
    it(`${label}: the isTrusted guard precedes any secret access`, () => {
      const start = content.indexOf(startAnchor);
      expect(start, `start anchor not found: ${startAnchor}`).toBeGreaterThanOrEqual(0);
      const end = content.indexOf(endAnchor, start + startAnchor.length);
      expect(end, `end anchor not found: ${endAnchor}`).toBeGreaterThan(start);

      const segment = content.slice(start, end);
      const guardAt = segment.indexOf(GUARD);
      const callAt = segment.indexOf(secretCall);
      expect(guardAt, `missing "${GUARD}" in ${label}`).toBeGreaterThanOrEqual(0);
      expect(callAt, `missing "${secretCall}" in ${label}`).toBeGreaterThanOrEqual(0);
      expect(guardAt, `guard must come before "${secretCall}" in ${label}`).toBeLessThan(
        callAt,
      );
    });
  }
});
