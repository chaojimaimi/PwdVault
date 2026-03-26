// PwdVault Background Service Worker
// Handles communication between content scripts, popup, and native app

const NATIVE_HOST_NAME = 'com.pwdvault.app';
const PORT_KEY = 'pwdvault_port';

let nativePort = null;
let connectionStatus = 'disconnected';
let pendingRequests = new Map();
let requestId = 0;

// ============================================================================
// Native Messaging
// ============================================================================

function connectToNativeApp() {
  if (nativePort) {
    return nativePort;
  }

  try {
    nativePort = chrome.runtime.connectNative(NATIVE_HOST_NAME);

    nativePort.onMessage.addListener((response) => {
      const { id, success, data, error } = response;

      if (pendingRequests.has(id)) {
        const { resolve, reject } = pendingRequests.get(id);
        pendingRequests.delete(id);

        if (success) {
          resolve(data);
        } else {
          reject(new Error(error || 'Unknown error'));
        }
      }
    });

    nativePort.onDisconnect.addListener(() => {
      nativePort = null;
      connectionStatus = 'disconnected';
      console.log('Disconnected from native app');

      // Reject all pending requests
      for (const [id, { reject }] of pendingRequests) {
        reject(new Error('Connection lost'));
      }
      pendingRequests.clear();
    });

    connectionStatus = 'connected';
    console.log('Connected to native app');
    return nativePort;
  } catch (error) {
    connectionStatus = 'disconnected';
    console.error('Failed to connect to native app:', error);
    return null;
  }
}

function sendToNativeApp(command, params = {}) {
  return new Promise((resolve, reject) => {
    if (!nativePort && !connectToNativeApp()) {
      reject(new Error('Cannot connect to native app'));
      return;
    }

    const id = ++requestId;
    pendingRequests.set(id, { resolve, reject });

    nativePort.postMessage({ id, command, ...params });

    // Timeout after 10 seconds
    setTimeout(() => {
      if (pendingRequests.has(id)) {
        pendingRequests.delete(id);
        reject(new Error('Request timeout'));
      }
    }, 10000);
  });
}

// ============================================================================
// API Wrappers
// ============================================================================

async function isVaultInitialized() {
  return sendToNativeApp('is_vault_initialized');
}

async function isVaultUnlocked() {
  return sendToNativeApp('is_vault_unlocked');
}

async function initVault(password) {
  return sendToNativeApp('init_vault', { password });
}

async function unlockVault(password) {
  return sendToNativeApp('unlock_vault', { password });
}

async function lockVault() {
  return sendToNativeApp('lock_vault');
}

async function createEntry(entry) {
  return sendToNativeApp('create_entry', {
    title: entry.title,
    url: entry.url,
    username: entry.username,
    password: entry.password,
    notes: entry.notes,
    tags: entry.tags || []
  });
}

async function getEntries() {
  return sendToNativeApp('list_all_entries');
}

async function getEntry(id) {
  return sendToNativeApp('get_entry', { id_param: id });
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
  return sendToNativeApp('generate_password', {
    length: options.length || 16,
    include_uppercase: options.uppercase !== false,
    include_lowercase: options.lowercase !== false,
    include_numbers: options.numbers !== false,
    include_symbols: options.symbols !== false,
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
        status: connectionStatus,
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
      connectToNativeApp();
      return { status: connectionStatus };

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

// Setup on install
chrome.runtime.onInstalled.addListener(() => {
  setupContextMenu();
  connectToNativeApp();
});

// Setup on startup
chrome.runtime.onStartup.addListener(() => {
  setupContextMenu();
  connectToNativeApp();
});

// Initial connection
setupContextMenu();
connectToNativeApp();