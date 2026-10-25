import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  authorizeMessage,
  entryMatchesPageUrl,
  entryMatchesSenderUrl,
} from './sender-auth.js';

const RUNTIME_ID = 'abcdefghijklmnopabcdefghijklmnop';

describe('extension sender authorization', () => {
  it('derives content URL from sender and allows only scoped read commands', () => {
    const sender = { id: RUNTIME_ID, tab: { url: 'https://example.com/login' } };
    expect(authorizeMessage({ type: 'GET_ENTRIES_FOR_URL', url: 'https://evil.test' }, sender, RUNTIME_ID))
      .toEqual({ senderKind: 'content', senderUrl: 'https://example.com/login' });
    expect(() => authorizeMessage({ type: 'GET_ENTRIES' }, sender, RUNTIME_ID)).toThrow();
    expect(() => authorizeMessage({ type: 'EXPORT_VAULT' }, sender, RUNTIME_ID)).toThrow();
  });

  it('prefers the frame URL (sender.url) over the top-level tab URL', () => {
    const sender = {
      id: RUNTIME_ID,
      url: 'https://login.example.com/inline-frame',
      tab: { url: 'https://top.example.com/page' },
    };
    expect(authorizeMessage({ type: 'GET_ENTRY', id: 'entry-1' }, sender, RUNTIME_ID))
      .toEqual({ senderKind: 'content', senderUrl: 'https://login.example.com/inline-frame' });
  });

  it('rejects cross-domain entry IDs before secret retrieval', () => {
    expect(entryMatchesSenderUrl({ url: 'https://example.com/account' }, 'https://www.example.com/login'))
      .toBe(true);
    expect(entryMatchesSenderUrl({ url: 'https://other.test/login' }, 'https://example.com/login'))
      .toBe(false);
    expect(entryMatchesSenderUrl({ url: null }, 'https://example.com/login')).toBe(false);
  });

  it('matches scheme-less stored entry URLs on the content path (v1.2.4)', () => {
    // Same scheme-padding semantics as entryMatchesPageUrl — a scheme-less
    // entry must not be invisible to auto-fill while the popup can fill it.
    expect(entryMatchesSenderUrl({ url: 'github.com/acme' }, 'https://github.com/login')).toBe(true);
    expect(entryMatchesSenderUrl({ url: 'other.test/login' }, 'https://github.com/login')).toBe(false);
    // Empty entryUrl stays REJECTED — intentional divergence from
    // entryMatchesPageUrl: auto-fill without a user click needs a URL to
    // compare against.
    expect(entryMatchesSenderUrl({ url: '' }, 'https://example.com/login')).toBe(false);
    expect(entryMatchesSenderUrl({}, 'https://example.com/login')).toBe(false);
  });

  it('accepts the popup but rejects another extension identity', () => {
    const popup = {
      id: RUNTIME_ID,
      url: `chrome-extension://${RUNTIME_ID}/src/popup/popup.html`,
    };
    expect(authorizeMessage({ type: 'EXPORT_VAULT' }, popup, RUNTIME_ID).senderKind).toBe('popup');
    expect(() => authorizeMessage({ type: 'GET_ENTRY' }, { ...popup, id: 'attacker' }, RUNTIME_ID))
      .toThrow();
  });
});

describe('entryMatchesPageUrl', () => {
  it('accepts an exact domain match', () => {
    expect(entryMatchesPageUrl('https://example.com/login', 'https://example.com/signin')).toBe(true);
    expect(entryMatchesPageUrl('https://example.com/login', 'https://example.com')).toBe(true);
  });

  it('rejects a different domain', () => {
    expect(entryMatchesPageUrl('https://example.com/account', 'https://evil.test/login')).toBe(false);
    expect(entryMatchesPageUrl('https://sub.example.com', 'https://example.com')).toBe(false);
  });

  it('pads a missing scheme with https:// like popup formatUrl', () => {
    expect(entryMatchesPageUrl('github.com/acme', 'https://github.com/login')).toBe(true);
    expect(entryMatchesPageUrl('http://example.com', 'https://example.com/x')).toBe(true);
    expect(entryMatchesPageUrl('other.test/login', 'https://github.com/login')).toBe(false);
  });

  it('rejects URLs that cannot be parsed (cannot judge)', () => {
    expect(entryMatchesPageUrl('https://', 'https://example.com')).toBe(false);
    expect(entryMatchesPageUrl('not a url', 'https://example.com')).toBe(false);
    expect(entryMatchesPageUrl('https://example.com', ':::bad:::')).toBe(false);
  });

  it('allows an empty entryUrl but rejects an empty pageUrl', () => {
    // Generic entry (no stored URL): an explicit popup fill is deliberate.
    expect(entryMatchesPageUrl('', 'https://example.com')).toBe(true);
    expect(entryMatchesPageUrl(null, 'https://example.com')).toBe(true);
    expect(entryMatchesPageUrl(undefined, 'https://example.com')).toBe(true);
    // No page URL = cannot judge = reject.
    expect(entryMatchesPageUrl('https://example.com', '')).toBe(false);
    expect(entryMatchesPageUrl('https://example.com', null)).toBe(false);
    expect(entryMatchesPageUrl('https://example.com', undefined)).toBe(false);
  });

  it('normalizes www and letter case like the other domain gates', () => {
    expect(entryMatchesPageUrl('https://www.example.com', 'https://example.com/x')).toBe(true);
    expect(entryMatchesPageUrl('https://example.com', 'https://www.example.com/x')).toBe(true);
    expect(entryMatchesPageUrl('https://WWW.Example.COM/login', 'https://www.EXAMPLE.com/x')).toBe(true);
    // Only a leading "www." is stripped — "www." inside is significant.
    expect(entryMatchesPageUrl('https://wwwexample.com', 'https://example.com')).toBe(false);
  });
});

describe('popup-only clipboard commands (v1.3.1)', () => {
  // The clipboard auto-clear arm and its failure-marker consumption schedule
  // clipboard destruction / reporting. They are internal popup↔background
  // messages: a content script (page-reachable code) must never reach them,
  // and they must never touch the desktop native-messaging channel.
  const popup = {
    id: RUNTIME_ID,
    url: `chrome-extension://${RUNTIME_ID}/src/popup/popup.html`,
  };
  const content = { id: RUNTIME_ID, tab: { url: 'https://example.com/login' } };

  it('accepts both commands from the popup', () => {
    expect(
      authorizeMessage(
        { type: 'CLIPBOARD_ARM_CLEAR', digest: 'ab'.repeat(32), deadline: 123 },
        popup,
        RUNTIME_ID,
      ).senderKind,
    ).toBe('popup');
    expect(
      authorizeMessage({ type: 'CONSUME_CLIPBOARD_CLEAR_FAILURE' }, popup, RUNTIME_ID)
        .senderKind,
    ).toBe('popup');
  });

  it('fails closed when a content script sends them', () => {
    expect(() =>
      authorizeMessage({ type: 'CLIPBOARD_ARM_CLEAR' }, content, RUNTIME_ID),
    ).toThrow();
    expect(() =>
      authorizeMessage({ type: 'CONSUME_CLIPBOARD_CLEAR_FAILURE' }, content, RUNTIME_ID),
    ).toThrow();
  });
});

describe('content.js verbatim copy guard', () => {
  // content.js is a classic script and cannot import this module; it carries
  // a hand-maintained copy of entryMatchesPageUrl. This test fails when the
  // copy drifts from the source of truth.
  it('content.js carries a byte-identical copy of entryMatchesPageUrl', () => {
    // node:url/node:path, NOT the global URL: under the jsdom test
    // environment `new URL(rel, import.meta.url)` resolves against the
    // jsdom document (http://localhost:3000), not the file base.
    const here = dirname(fileURLToPath(import.meta.url));
    const source = readFileSync(join(here, 'sender-auth.js'), 'utf8');
    const content = readFileSync(join(here, 'content.js'), 'utf8');
    const fn = source.match(/export function entryMatchesPageUrl\(entryUrl, pageUrl\) \{[\s\S]*?\n\}/);
    expect(fn).not.toBeNull();
    expect(content).toContain(fn[0].replace('export ', ''));
  });
});
