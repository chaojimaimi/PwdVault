import { describe, expect, it, vi } from 'vitest';
import { createTokenStorage } from './token-storage.js';

function area(initial = {}) {
  const values = { ...initial };
  return {
    setAccessLevel: vi.fn().mockResolvedValue(undefined),
    get: vi.fn(async key => ({ [key]: values[key] })),
    set: vi.fn(async update => Object.assign(values, update)),
    remove: vi.fn(async key => delete values[key]),
  };
}

describe('trusted token storage', () => {
  it('prefers restricted session storage', async () => {
    const session = area();
    const local = area();
    const storage = await createTokenStorage({ session, local }, 'token');
    await storage.save('secret');
    expect(storage.kind).toBe('session');
    expect(session.setAccessLevel).toHaveBeenCalledWith({ accessLevel: 'TRUSTED_CONTEXTS' });
    expect(await storage.load()).toBe('secret');
    expect(local.set).not.toHaveBeenCalled();
  });

  it('uses local only when trusted-context restriction succeeds', async () => {
    const local = area();
    const storage = await createTokenStorage({ local }, 'token');
    expect(storage.kind).toBe('local');
    expect(local.setAccessLevel).toHaveBeenCalled();
  });

  it('falls back to memory instead of content-readable local storage', async () => {
    const local = area();
    delete local.setAccessLevel;
    const storage = await createTokenStorage({ local }, 'token');
    await storage.save('secret');
    expect(storage.kind).toBe('memory');
    expect(await storage.load()).toBeNull();
    expect(local.set).not.toHaveBeenCalled();
  });
});
