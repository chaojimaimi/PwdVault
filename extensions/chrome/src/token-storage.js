const TRUSTED_CONTEXTS = 'TRUSTED_CONTEXTS';

async function restrictToTrustedContexts(area) {
  if (typeof area?.setAccessLevel !== 'function') return false;
  await area.setAccessLevel({ accessLevel: TRUSTED_CONTEXTS });
  return true;
}

/// Select storage that content scripts cannot read. `storage.session` is
/// preferred because it survives MV3 worker suspension but clears on browser
/// restart. Local persistence is used only when its access level can be
/// explicitly restricted; otherwise the token remains memory-only.
export async function createTokenStorage(storageApi, key) {
  let area = null;
  let legacyLocal = null;

  if (storageApi?.session) {
    try {
      // Chrome session storage is trusted-context-only by default; still set
      // it explicitly where supported so the boundary is self-documenting.
      if (typeof storageApi.session.setAccessLevel === 'function') {
        await restrictToTrustedContexts(storageApi.session);
      }
      area = storageApi.session;
    } catch {
      area = null;
    }
  }

  if (!area && storageApi?.local) {
    try {
      if (await restrictToTrustedContexts(storageApi.local)) area = storageApi.local;
    } catch {
      area = null;
    }
  }

  // Secure or delete any token left by older versions in storage.local before
  // content scripts get a chance to read it. When restriction succeeds we can
  // migrate it into session storage on first load.
  if (area === storageApi?.session && storageApi?.local) {
    try {
      if (await restrictToTrustedContexts(storageApi.local)) legacyLocal = storageApi.local;
      else await storageApi.local.remove(key);
    } catch {
      try { await storageApi.local.remove(key); } catch { /* best effort */ }
    }
  }

  return {
    kind: area === storageApi?.session ? 'session' : area ? 'local' : 'memory',
    async load() {
      if (!area) return null;
      const result = await area.get(key);
      if (typeof result?.[key] === 'string') return result[key];
      if (legacyLocal) {
        const legacy = await legacyLocal.get(key);
        if (typeof legacy?.[key] === 'string') {
          await area.set({ [key]: legacy[key] });
          await legacyLocal.remove(key);
          return legacy[key];
        }
      }
      return null;
    },
    async save(token) {
      if (!area) return;
      if (token) await area.set({ [key]: token });
      else await area.remove(key);
    },
  };
}
