// PwdVault Background Service Worker
// Handles communication between content scripts, popup, and desktop app via
// Native Messaging (the browser spawns a host binary that bridges to the
// desktop app's local HTTP API on 127.0.0.1:17429).

// The native messaging host name; must match the "name" field in the manifest
// registered by the desktop app (native_host_setup.rs).
const NATIVE_HOST = 'com.pwdvault.app';

// Storage key for persisting the pairing token across service worker
// restarts. MV3 service workers are killed by Chrome after ~30s idle; if
// we don't persist the token, the user would be forced to re-pair after
// every restart.
const TOKEN_STORAGE_KEY = 'pwdvault_api_token';

let connectionStatus = 'disconnected';
let requestId = 0;
let apiToken = null;

// Persist/restore the token via chrome.storage.local. These are no-ops in
// contexts where the storage API is unavailable (e.g. unit tests).
function saveToken(token) {
  apiToken = token;
  try {
    if (token) {
      chrome.storage.local.set({ [TOKEN_STORAGE_KEY]: token });
    } else {
      chrome.storage.local.remove(TOKEN_STORAGE_KEY);
    }
  } catch (e) {
    // storage API may be unavailable in some test contexts — ignore.
  }
}

async function restoreToken() {
  try {
    const result = await chrome.storage.local.get(TOKEN_STORAGE_KEY);
    if (result && result[TOKEN_STORAGE_KEY]) {
      apiToken = result[TOKEN_STORAGE_KEY];
      return true;
    }
  } catch (e) {
    // ignore
  }
  return false;
}

// ============================================================================
// Native Messaging Communication
// ============================================================================

// sendNativeMessage is promise-based in Firefox (chrome.runtime.sendMessage is
// promise-based too in MV3). We wrap it to normalize the response shape and
// apply a timeout so a hung host doesn't block the caller indefinitely.
const NM_TIMEOUT_MS = 30000;

function sendNativeMessageP(message) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        chrome.runtime.lastError; // clear any pending error
        reject(new Error('Native messaging host timed out'));
      }
    }, NM_TIMEOUT_MS);

    try {
      chrome.runtime.sendNativeMessage(NATIVE_HOST, message, (response) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);

        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        resolve(response);
      });
    } catch (e) {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        reject(e);
      }
    }
  });
}

// Pairing flow: pair → desktop app shows 6-digit code → user enters code
// in popup → pair_confirm → server returns API token.
// Returns 'paired' | 'needs_code' | 'failed'.
async function pairWithApp() {
  try {
    const data = await sendNativeMessageP({ id: 0, command: 'pair' });
    if (data && data.success && data.data) {
      if (data.data.token) {
        saveToken(data.data.token);
        return 'paired';
      }
      if (data.data.pending) {
        return 'needs_code';
      }
    }
    return 'failed';
  } catch {
    return 'failed';
  }
}

// Submit the user-entered 6-digit code to complete pairing.
async function pairConfirm(code) {
  try {
    const data = await sendNativeMessageP({ id: 0, command: 'pair_confirm', code });
    if (data && data.success && data.data && data.data.token) {
      saveToken(data.data.token);
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

async function sendToApp(command, params = {}) {
  const id = ++requestId;

  // Pairing commands bypass auth; all other commands require a token.
  if (!apiToken && command !== 'pair' && command !== 'pair_confirm') {
    throw new Error('Not paired with desktop app');
  }

  // Native Messaging has no HTTP headers, so the Bearer token travels in the
  // body as `auth_token`. The host binary lifts it into an Authorization header
  // before forwarding to the desktop app's HTTP API.
  const message = { id, command, ...params };
  if (apiToken) {
    message.auth_token = apiToken;
  }

  try {
    const data = await sendNativeMessageP(message);

    if (data && data.success) {
      connectionStatus = 'connected';
      return data.data;
    } else {
      throw new Error((data && data.error) || 'Unknown error');
    }
  } catch (error) {
    const msg = error.message || '';
    if (msg.includes('native messaging') || msg.includes('not found') ||
        msg.includes('timed out') || msg.includes('connect')) {
      connectionStatus = 'disconnected';
      throw new Error('Cannot connect to PwdVault desktop app. Is it running?');
    }
    throw error;
  }
}

async function checkConnection() {
  // Ensure the persisted token is restored before evaluating connection
  // state. The service worker may have just been spun up by Chrome and
  // `restoreToken()` (called fire-and-forget at SW startup) may not have
  // completed yet. Without this await, the popup would see `apiToken === null`
  // and wrongly force the user back into the pairing flow.
  await restoreToken();

  // If we have a token, verify it still works.
  if (apiToken) {
    try {
      await sendToApp('is_vault_initialized');
      connectionStatus = 'connected';
      return connectionStatus;
    } catch {
      // Token rejected or app unreachable — clear it so a fresh pairing
      // can be initiated.
      saveToken(null);
    }
  }
  // No token — needs pairing. Do NOT call `pair` here: each `pair` call
  // creates a new session and overwrites the previous code, invalidating
  // any code the desktop app is currently displaying. The popup must
  // trigger pairing explicitly via START_PAIRING when the user is ready
  // to enter the code.
  connectionStatus = 'needs_pairing';
  return connectionStatus;
}

// Explicitly initiate pairing: asks the desktop app to display a 6-digit
// code. Should be called only when the user is on the pairing screen and
// ready to enter the code, to avoid creating competing sessions.
async function startPairing() {
  const result = await pairWithApp();
  if (result === 'paired') {
    connectionStatus = 'connected';
  } else if (result === 'needs_code') {
    connectionStatus = 'needs_pairing';
  } else {
    connectionStatus = 'disconnected';
  }
  return result;
}

// ============================================================================
// API Wrappers
// ============================================================================

async function isVaultInitialized() {
  return sendToApp('is_vault_initialized');
}

async function isVaultUnlocked() {
  return sendToApp('is_vault_unlocked');
}

async function initVault(password) {
  return sendToApp('init_vault', { password });
}

async function unlockVault(password) {
  return sendToApp('unlock_vault', { password });
}

async function lockVault() {
  return sendToApp('lock_vault');
}

async function createEntry(entry) {
  return sendToApp('create_entry', {
    title: entry.title,
    url: entry.url,
    username: entry.username,
    password: entry.password,
    notes: entry.notes,
    tags: entry.tags || [],
    group_id: entry.group_id || null,
  });
}

// Group API wrappers
async function getGroups() {
  return sendToApp('list_all_groups');
}

async function createGroup(name) {
  return sendToApp('create_group', { name });
}

async function updateGroup(id, name) {
  return sendToApp('update_group', { id_param: id, name });
}

async function deleteGroup(id) {
  return sendToApp('remove_group', { id_param: id });
}

async function getSettings() {
  return sendToApp('get_settings');
}

async function updateSettings(settings) {
  return sendToApp('update_settings', { settings });
}

async function exportVault(exportPassword) {
  return sendToApp('export_vault', { export_password: exportPassword });
}

async function importVault(backup, importPassword) {
  return sendToApp('import_vault', { backup, import_password: importPassword });
}

async function getEntries() {
  return sendToApp('list_all_entries');
}

async function getEntry(id) {
  // B4 split get_entry into get_entry_meta (no password) and get_entry_secret
  // (password/notes/last_used_at). Fetch both and merge so callers keep
  // getting the full entry shape they expect.
  //
  // Use allSettled so a secret-fetch failure (e.g. transient backend error)
  // does not take down the meta fetch — the user still sees title/username/url,
  // and password simply falls back to empty.
  const [metaRes, secretRes] = await Promise.allSettled([
    sendToApp('get_entry_meta', { id_param: id }),
    sendToApp('get_entry_secret', { id_param: id }),
  ]);
  if (metaRes.status !== 'fulfilled' || !metaRes.value) return null;
  const secret = secretRes.status === 'fulfilled' ? secretRes.value : null;
  return {
    ...metaRes.value,
    password: secret ? secret.password : '',
    notes: secret ? secret.notes : null,
    last_used_at: secret ? secret.last_used_at : null,
  };
}

async function getEntriesForUrl(url) {
  const entries = await getEntries();
  const urlObj = new URL(url);
  const domain = urlObj.hostname.replace('www.', '');

  return entries.filter(entry => {
    if (!entry.url) return false;
    try {
      const entryDomain = new URL(entry.url).hostname.replace('www.', '');
      return entryDomain === domain;
    } catch {
      return false;
    }
  });
}

async function generatePassword(options = {}) {
  return sendToApp('generate_password', {
    options: {
      length: options.length || 16,
      include_uppercase: options.uppercase !== false,
      include_lowercase: options.lowercase !== false,
      include_numbers: options.numbers !== false,
      include_symbols: options.symbols !== false,
    },
  });
}

// ============================================================================
// Context Menu
// ============================================================================

function setupContextMenu() {
  // Wrap in try/catch: the contextMenus API can throw if the extension
  // isn't yet fully initialized or if the API is unavailable in a given
  // context. A thrown error here would abort the entire onInstalled /
  // onStartup / SW-startup handler, preventing token restoration and
  // other initialization from running.
  try {
    chrome.contextMenus.removeAll(() => {
      try {
        chrome.contextMenus.create({
          id: 'pwdvault-fill',
          title: 'Fill with PwdVault',
          contexts: ['editable'],
        });

        chrome.contextMenus.create({
          id: 'pwdvault-generate',
          title: 'Generate Password',
          contexts: ['editable'],
        });
      } catch (e) {
        // contextMenus.create can throw if an entry already exists or if
        // the API is temporarily unavailable — non-fatal.
      }
    });
  } catch (e) {
    // contextMenus API unavailable — non-fatal; the popup still works.
  }
}

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === 'pwdvault-fill') {
    const entries = await getEntriesForUrl(tab.url);
    if (entries.length > 0) {
      const entry = await getEntry(entries[0].id);
      chrome.tabs.sendMessage(tab.id, {
        type: 'AUTOFILL',
        username: entry.username,
        password: entry.password,
      });
    }
  } else if (info.menuItemId === 'pwdvault-generate') {
    const password = await generatePassword();
    chrome.tabs.sendMessage(tab.id, {
      type: 'INSERT_PASSWORD',
      password,
    });
  }
});

// ============================================================================
// Message Handling
// ============================================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender)
    .then(sendResponse)
    .catch((error) => sendResponse({ error: error.message }));
  return true; // Keep channel open for async response
});

async function handleMessage(message, sender) {
  switch (message.type) {
    case 'GET_STATUS':
      return {
        status: await checkConnection(),
        initialized: await isVaultInitialized().catch(() => false),
        unlocked: await isVaultUnlocked().catch(() => false),
      };

    case 'INIT_VAULT':
      return initVault(message.password);

    case 'UNLOCK_VAULT':
      return unlockVault(message.password);

    case 'LOCK_VAULT':
      return lockVault();

    case 'CREATE_ENTRY':
      return createEntry(message.entry);

    case 'GET_ENTRIES':
      return getEntries();

    case 'GET_ENTRIES_FOR_URL':
      return getEntriesForUrl(message.url);

    case 'GET_ENTRY':
      return getEntry(message.id);

    case 'GENERATE_PASSWORD':
      return generatePassword(message.options);

    case 'GET_GROUPS':
      return getGroups();

    case 'CREATE_GROUP':
      return createGroup(message.name);

    case 'UPDATE_GROUP':
      return updateGroup(message.id, message.name);

    case 'DELETE_GROUP':
      return deleteGroup(message.id);

    case 'GET_SETTINGS':
      return getSettings();

    case 'UPDATE_SETTINGS':
      return updateSettings(message.settings);

    case 'EXPORT_VAULT':
      return exportVault(message.exportPassword);

    case 'IMPORT_VAULT':
      return importVault(message.backup, message.importPassword);

    case 'AUTOFILL':
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab) {
        chrome.tabs.sendMessage(tab.id, {
          type: 'AUTOFILL',
          username: message.username,
          password: message.password,
        });
      }
      return { success: true };

    case 'CONNECT':
      return { status: await checkConnection() };

    case 'START_PAIRING':
      const pairResult = await startPairing();
      return { result: pairResult, status: connectionStatus };

    case 'PAIR_CONFIRM':
      const ok = await pairConfirm(message.code);
      if (ok) {
        return { success: true };
      }
      return { success: false, error: 'Invalid or expired code' };

    default:
      throw new Error(`Unknown message type: ${message.type}`);
  }
}

// ============================================================================
// Keyboard Shortcuts
// ============================================================================

chrome.commands.onCommand.addListener(async (command) => {
  if (command === 'autofill') {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab) {
      try {
        const entries = await getEntriesForUrl(tab.url);
        if (entries.length > 0) {
          const entry = await getEntry(entries[0].id);
          chrome.tabs.sendMessage(tab.id, {
            type: 'AUTOFILL',
            username: entry.username,
            password: entry.password,
          });
        }
      } catch (error) {
        console.error('Autofill failed:', error);
      }
    }
  }
});

// ============================================================================
// Initialization
// ============================================================================

// NOTE: Do NOT call checkConnection() on service worker startup. In MV3 the
// service worker is terminated and restarted frequently; each restart would
// trigger `pair` (via checkConnection → pairWithApp), creating a new session
// and invalidating any code the desktop app is currently displaying. Pairing
// is initiated explicitly by the popup via START_PAIRING when the user is
// ready to enter the code.

chrome.runtime.onInstalled.addListener((details) => {
  setupContextMenu();
  // Only clear the token on a genuine first install. Clearing on every
  // `onInstalled` (which also fires for updates and Chrome updates) would
  // force the user to re-pair after every extension upgrade, even though
  // the persisted token is still valid.
  if (details.reason === 'install') {
    saveToken(null);
  }
});

chrome.runtime.onStartup.addListener(() => {
  setupContextMenu();
  // Restore the persisted token when the browser starts so the user does
  // not have to re-pair every browser launch.
  restoreToken();
});

// Service worker startup (including restarts after being killed by Chrome
// for idleness): restore the token before serving any popup requests.
// restoreToken is async but we don't await here — the popup will retry
// CONNECT and checkConnection will handle the not-yet-restored case.
setupContextMenu();
restoreToken();
