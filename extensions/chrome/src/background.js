// PwdVault Background Service Worker
// Handles communication between content scripts, popup, and desktop app via
// Native Messaging (the browser spawns a host binary that bridges to the
// desktop app's local HTTP API on 127.0.0.1:17429).

// The native messaging host name; must match the "name" field in the manifest
// registered by the desktop app (native_host_setup.rs).
const NATIVE_HOST = 'com.pwdvault.app';

let connectionStatus = 'disconnected';
let requestId = 0;
let apiToken = null;

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

async function pairWithApp() {
  try {
    const data = await sendNativeMessageP({ id: 0, command: 'pair' });
    if (data && data.success && data.data && data.data.token) {
      apiToken = data.data.token;
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

async function sendToApp(command, params = {}) {
  const id = ++requestId;

  // If we don't have a token yet, try to pair first
  if (!apiToken && command !== 'pair') {
    await pairWithApp();
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
  try {
    await pairWithApp();
    await sendToApp('is_vault_initialized');
    connectionStatus = 'connected';
  } catch {
    connectionStatus = 'disconnected';
  }
  return connectionStatus;
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
  return sendToApp('get_entry', { id_param: id });
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
  chrome.contextMenus.removeAll(() => {
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
  });
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

chrome.runtime.onInstalled.addListener(() => {
  setupContextMenu();
  checkConnection();
});

chrome.runtime.onStartup.addListener(() => {
  setupContextMenu();
  checkConnection();
});

setupContextMenu();
checkConnection();
