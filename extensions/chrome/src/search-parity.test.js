import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
// Desktop fuse config (TypeScript) imported directly — same two-end parity
// pattern as password-strength.test.js: any edit to the desktop options that
// is not mirrored in the popup fails here.
import { fuseOptions } from '../../../src/utils/search';

const here = dirname(fileURLToPath(import.meta.url));

// popup.js touches chrome.* at import time (and constructs PopupApp), so the
// popup-side options cannot be imported — extract the object literal from the
// source text instead. The extraction throws if the constant is renamed or
// moved, and any edit to the literal changes what gets compared.
const popupSource = readFileSync(join(here, 'popup', 'popup.js'), 'utf8');
const match = popupSource.match(/const FUSE_SEARCH_OPTIONS = (\{[\s\S]*?\n\});/);
if (!match) {
  throw new Error('FUSE_SEARCH_OPTIONS not found in popup/popup.js');
}
const popupOptions = new Function(`return ${match[1]}`)();

describe('popup fuse options parity with the desktop', () => {
  it('keeps every field in sync with src/utils/search.ts', () => {
    expect(popupOptions.keys).toEqual(fuseOptions.keys);
    expect(popupOptions.threshold).toBe(fuseOptions.threshold);
    expect(popupOptions.includeScore).toBe(fuseOptions.includeScore);
    expect(popupOptions.ignoreLocation).toBe(fuseOptions.ignoreLocation);
  });

  it('matches the desktop config object exactly', () => {
    expect(popupOptions).toEqual(fuseOptions);
  });
});
