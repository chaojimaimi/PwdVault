import { describe, expect, it, vi } from 'vitest';
import { createPairNonceStorage } from './pair-nonce-storage.js';

function sessionArea(initial = {}) {
  const values = { ...initial };
  return {
    setAccessLevel: vi.fn().mockResolvedValue(undefined),
    get: vi.fn(async key => ({ [key]: values[key] })),
    set: vi.fn(async update => Object.assign(values, update)),
    remove: vi.fn(async key => delete values[key]),
  };
}

describe('pairing nonce storage', () => {
  it('saves and loads the pending nonce in session storage', async () => {
    const session = sessionArea();
    const storage = await createPairNonceStorage({ session }, 'nonce');
    await storage.save('nonce-123456');
    expect(storage.kind).toBe('session');
    expect(session.setAccessLevel).toHaveBeenCalledWith({ accessLevel: 'TRUSTED_CONTEXTS' });
    expect(await storage.load()).toBe('nonce-123456');
  });

  it('returns null when no nonce is stored', async () => {
    const session = sessionArea();
    const storage = await createPairNonceStorage({ session }, 'nonce');
    expect(await storage.load()).toBeNull();
  });

  it('clears the nonce on save(null)', async () => {
    const session = sessionArea();
    const storage = await createPairNonceStorage({ session }, 'nonce');
    await storage.save('nonce-123456');
    await storage.save(null);
    expect(session.remove).toHaveBeenCalledWith('nonce');
    expect(await storage.load()).toBeNull();
  });

  it('falls back to memory when session storage is unavailable', async () => {
    const storage = await createPairNonceStorage({}, 'nonce');
    await storage.save('nonce-123456');
    expect(storage.kind).toBe('memory');
    expect(await storage.load()).toBeNull();
  });
});
