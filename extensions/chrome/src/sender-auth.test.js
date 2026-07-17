import { describe, expect, it } from 'vitest';
import { authorizeMessage, entryMatchesSenderUrl } from './sender-auth.js';

const RUNTIME_ID = 'abcdefghijklmnopabcdefghijklmnop';

describe('extension sender authorization', () => {
  it('derives content URL from sender and allows only scoped read commands', () => {
    const sender = { id: RUNTIME_ID, tab: { url: 'https://example.com/login' } };
    expect(authorizeMessage({ type: 'GET_ENTRIES_FOR_URL', url: 'https://evil.test' }, sender, RUNTIME_ID))
      .toEqual({ senderKind: 'content', senderUrl: 'https://example.com/login' });
    expect(() => authorizeMessage({ type: 'GET_ENTRIES' }, sender, RUNTIME_ID)).toThrow();
    expect(() => authorizeMessage({ type: 'EXPORT_VAULT' }, sender, RUNTIME_ID)).toThrow();
  });

  it('rejects cross-domain entry IDs before secret retrieval', () => {
    expect(entryMatchesSenderUrl({ url: 'https://example.com/account' }, 'https://www.example.com/login'))
      .toBe(true);
    expect(entryMatchesSenderUrl({ url: 'https://other.test/login' }, 'https://example.com/login'))
      .toBe(false);
    expect(entryMatchesSenderUrl({ url: null }, 'https://example.com/login')).toBe(false);
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
