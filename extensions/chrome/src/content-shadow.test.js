import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

// Source-guard test (same style as content-is-trusted.test.js): content.js is
// a classic content script that cannot run under jsdom's test harness, so the
// v1.3.2 Shadow DOM isolation contract is asserted on the source text.
//
// Contract: every injected UI root (auto-fill bar, overlay, toast, floating
// button) mounts inside its own closed shadow root seeded from ONE shared CSS
// constant; no style reaches the host page's document; the palette is the
// desktop Light theme mirror instead of the retired indigo/dark set.
const here = dirname(fileURLToPath(import.meta.url));
const content = readFileSync(join(here, 'content.js'), 'utf8');

const UI_ROOTS = 4;

describe('content.js shadow DOM isolation (v1.3.2)', () => {
  it('mounts exactly one closed shadow root per UI root (4 total)', () => {
    // Single choke point: mountShadowHost is the only place a shadow root is
    // created, and it is invoked exactly once per UI root.
    expect(content.split('attachShadow({ mode: "closed" })').length - 1).toBe(1);
    expect(content.split('mountShadowHost(').length - 1).toBe(UI_ROOTS + 1); // helper def + UI_ROOTS calls
  });

  it('never injects a <style> into the host page', () => {
    // v1.3.1 regression guard: the toast used to append a fresh <style> to
    // document.head on EVERY call (unbounded accumulation). Style now lives
    // only inside the shadow roots.
    expect(content).not.toContain('document.head.appendChild');
    // Exactly one <style> element is ever created — the shared one that
    // mountShadowHost seeds into each shadow root.
    expect(content.split('document.createElement("style")').length - 1).toBe(1);
  });

  it('retires the indigo/dark palette and carries the desktop Light mirror', () => {
    for (const retired of ['#6366f1', '#8b5cf6', '#4f46e5', '#1e1e2e', '#2d2d44', '#262637']) {
      expect(content).not.toContain(retired);
    }
    // The :host token block mirrors themes.css Light (primary navy + teal accent).
    expect(content).toContain('#1E3A5F');
    expect(content).toContain('#0D9488');
    expect(content).toContain('--pv-primary: #1E3A5F');
    expect(content).toContain('--pv-accent: #0D9488');
  });

  it('keeps the four keyframes inside the shared shadow CSS constant only', () => {
    for (const name of ['slideDown', 'fadeIn', 'slideIn', 'fadeInFloat']) {
      // Exactly one definition — inside SHADOW_CSS; no per-toast/per-bar
      // "<style>@keyframes …" injection statements remain. The trailing
      // brace keeps "fadeIn" from prefix-matching "fadeInFloat".
      expect(content.split(`@keyframes ${name} {`).length - 1).toBe(1);
    }
  });
});
