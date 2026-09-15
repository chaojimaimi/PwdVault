const TRUSTED_CONTEXTS = 'TRUSTED_CONTEXTS';
const DEFAULT_PAIR_NONCE_KEY = 'pwdvault_pair_nonce';

/// Persist the pending pairing nonce so `pair_confirm` can still complete
/// after the MV3 service worker is killed while the user types the 6-digit
/// code shown by the desktop app. `storage.session` survives worker
/// suspension but intentionally clears on a full browser restart; when it is
/// unavailable the nonce stays memory-only (same trade-off as the API token).
export async function createPairNonceStorage(storageApi, key = DEFAULT_PAIR_NONCE_KEY) {
  let area = null;

  if (storageApi?.session) {
    try {
      // Match token-storage.js: keep the value trusted-context-only where
      // the API is supported so content scripts cannot read it.
      if (typeof storageApi.session.setAccessLevel === 'function') {
        await storageApi.session.setAccessLevel({ accessLevel: TRUSTED_CONTEXTS });
      }
      area = storageApi.session;
    } catch {
      area = null;
    }
  }

  return {
    kind: area ? 'session' : 'memory',
    async load() {
      if (!area) return null;
      try {
        const result = await area.get(key);
        const nonce = result?.[key];
        return typeof nonce === 'string' && nonce ? nonce : null;
      } catch {
        return null;
      }
    },
    async save(nonce) {
      if (!area) return;
      try {
        if (nonce) await area.set({ [key]: nonce });
        else await area.remove(key);
      } catch {
        // Best effort: the in-memory cache still covers the common case.
      }
    },
  };
}
