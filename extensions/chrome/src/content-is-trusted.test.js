import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

// content.js is a classic content script (no module export, top-level DOM
// access), so like the sender-auth verbatim guard this test asserts on the
// source text: every handler that can pull plaintext credentials must begin
// with the isTrusted gate, before any secret-fetching call. jsdom cannot run
// these handlers (isTrusted is always false there), so the source contract is
// what keeps a synthetic-event refactor from silently dropping the gate.
const here = dirname(fileURLToPath(import.meta.url));
const content = readFileSync(join(here, 'content.js'), 'utf8');

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
    'Auto-fill Prompt Logic',
    'showOverlay(',
  ],
];

describe('content.js isTrusted source guard', () => {
  it('carries exactly the four credential-triggering guards', () => {
    // Exact count: a fifth secret-touching handler must add its guard AND
    // register it here — silent additions fail this assertion.
    expect(content.split(GUARD).length - 1).toBe(4);
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
