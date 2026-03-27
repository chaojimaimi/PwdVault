// PwdVault Popup Script - Enhanced Version

class PopupApp {
  constructor() {
    this.state = {
      status: 'loading',
      unlocked: false,
      entries: [],
      entryDetails: new Map(), // Cache for full entry details
      searchQuery: '',
      error: null,
      expandedEntryId: null,
      visiblePasswords: new Set(), // Track which passwords are visible
    };

    this.init();
  }

  async init() {
    try {
      const status = await this.sendMessage({ type: 'GET_STATUS' });

      if (status.unlocked) {
        this.state.status = 'unlocked';
        this.state.unlocked = true;
        await this.loadEntries();
      } else if (status.status === 'connected') {
        this.state.status = 'locked';
      } else {
        this.state.status = 'disconnected';
      }

      this.render();
    } catch (error) {
      this.state.status = 'error';
      this.state.error = error.message;
      this.render();
    }
  }

  async sendMessage(message) {
    return chrome.runtime.sendMessage(message);
  }

  async loadEntries() {
    try {
      const entries = await this.sendMessage({ type: 'GET_ENTRIES' });
      if (entries && entries.error) {
        this.state.error = entries.error;
      } else {
        this.state.entries = entries || [];
      }
    } catch (error) {
      this.state.error = error.message;
    }
  }

  async getEntryDetails(id) {
    if (this.state.entryDetails.has(id)) {
      return this.state.entryDetails.get(id);
    }

    try {
      const entry = await this.sendMessage({ type: 'GET_ENTRY', id });
      if (entry && !entry.error) {
        this.state.entryDetails.set(id, entry);
        return entry;
      }
    } catch (error) {
      console.error('Failed to get entry details:', error);
    }
    return null;
  }

  async unlock(password) {
    this.state.status = 'loading';
    this.render();

    try {
      const result = await this.sendMessage({ type: 'UNLOCK_VAULT', password });
      if (result === true) {
        this.state.unlocked = true;
        this.state.status = 'unlocked';
        this.state.error = null;
        await this.loadEntries();
      } else {
        this.state.error = 'Invalid password';
        this.state.status = 'locked';
      }
    } catch (error) {
      this.state.error = error.message;
      this.state.status = 'locked';
    }

    this.render();
  }

  async lock() {
    await this.sendMessage({ type: 'LOCK_VAULT' });
    this.state.unlocked = false;
    this.state.status = 'locked';
    this.state.entries = [];
    this.state.entryDetails.clear();
    this.state.expandedEntryId = null;
    this.state.visiblePasswords.clear();
    this.render();
  }

  async autofill(entry) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab) {
      // Get full entry with password
      const fullEntry = await this.getEntryDetails(entry.id);
      if (fullEntry && fullEntry.password) {
        chrome.tabs.sendMessage(tab.id, {
          type: 'AUTOFILL',
          username: fullEntry.username,
          password: fullEntry.password,
        });
        window.close();
      }
    }
  }

  async copyToClipboard(text, label = 'Copied!', autoClear = false) {
    try {
      await navigator.clipboard.writeText(text);

      // Auto-clear clipboard after 30 seconds for sensitive data
      if (autoClear) {
        setTimeout(async () => {
          try {
            const current = await navigator.clipboard.readText();
            if (current === text) {
              await navigator.clipboard.writeText('');
            }
          } catch {
            // Clipboard access denied or text already changed
          }
        }, 30000);
        this.showToast(label + ' (auto-clears in 30s)');
      } else {
        this.showToast(label);
      }
      return true;
    } catch {
      this.showToast('Failed to copy');
      return false;
    }
  }

  showToast(message) {
    const toast = document.getElementById('toast');
    const messageEl = document.getElementById('toast-message');
    messageEl.textContent = message;
    toast.classList.add('show');

    setTimeout(() => {
      toast.classList.remove('show');
    }, 2000);
  }

  getFilteredEntries() {
    if (!this.state.searchQuery) return this.state.entries;

    const query = this.state.searchQuery.toLowerCase();
    return this.state.entries.filter(entry => {
      const title = (entry.title || '').toLowerCase();
      const username = (entry.username || '').toLowerCase();
      const url = (entry.url || '').toLowerCase();

      return title.includes(query) ||
             username.includes(query) ||
             url.includes(query);
    });
  }

  toggleEntryExpansion(entryId) {
    if (this.state.expandedEntryId === entryId) {
      this.state.expandedEntryId = null;
    } else {
      this.state.expandedEntryId = entryId;
      // Clear password visibility when expanding new entry
      this.state.visiblePasswords.clear();
      // Pre-load entry details
      this.getEntryDetails(entryId);
    }
    this.render();
  }

  togglePasswordVisibility(entryId) {
    if (this.state.visiblePasswords.has(entryId)) {
      this.state.visiblePasswords.delete(entryId);
    } else {
      this.state.visiblePasswords.add(entryId);
    }
    this.render();
  }

  async goToUrl(url) {
    if (url) {
      let finalUrl = url;
      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        finalUrl = 'https://' + url;
      }
      chrome.tabs.create({ url: finalUrl });
      window.close();
    }
  }

  render() {
    const app = document.getElementById('app');

    switch (this.state.status) {
      case 'loading':
        app.innerHTML = this.renderLoading();
        break;
      case 'locked':
        app.innerHTML = this.renderLockScreen();
        this.attachLockScreenEvents();
        break;
      case 'unlocked':
        app.innerHTML = this.renderMain();
        this.attachMainEvents();
        break;
      case 'disconnected':
        app.innerHTML = this.renderDisconnected();
        this.attachDisconnectedEvents();
        break;
      default:
        app.innerHTML = this.renderError();
    }
  }

  renderLoading() {
    return `
      <div class="loading">
        <div class="spinner"></div>
        <span>Loading...</span>
      </div>
    `;
  }

  renderLockScreen() {
    return `
      <div class="lock-screen">
        <div class="lock-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0110 0v4"/>
          </svg>
        </div>
        <h2>Vault Locked</h2>
        <p>Enter your master password to unlock</p>

        ${this.state.error ? `<div class="error-message">${this.escapeHtml(this.state.error)}</div>` : ''}

        <form id="unlock-form">
          <div class="form-group">
            <label for="password">Master Password</label>
            <input
              type="password"
              id="password"
              class="form-input"
              placeholder="Enter password"
              autofocus
            />
          </div>
          <button type="submit" class="btn btn-primary">Unlock Vault</button>
        </form>
      </div>
    `;
  }

  renderMain() {
    const entries = this.getFilteredEntries();

    return `
      <div class="header">
        <div class="header-brand">
          <div class="header-logo">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
              <path d="M7 11V7a5 5 0 0110 0v4"/>
            </svg>
          </div>
          <h1>PwdVault</h1>
        </div>
        <div class="header-actions">
          <button class="icon-btn" id="generator-btn" title="Generate Password">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 2v4m0 12v4M4.93 4.93l2.83 2.83m8.48 8.48l2.83 2.83M2 12h4m12 0h4M4.93 19.07l2.83-2.83m8.48-8.48l2.83-2.83"/>
            </svg>
          </button>
          <button class="icon-btn danger" id="lock-btn" title="Lock Vault">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
              <path d="M7 11V7a5 5 0 0110 0v4"/>
            </svg>
          </button>
        </div>
      </div>

      <div class="content">
        <div class="search-wrapper">
          <svg class="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="11" cy="11" r="8"/>
            <line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <input
            type="text"
            class="search"
            id="search"
            placeholder="Search passwords..."
            value="${this.escapeHtml(this.state.searchQuery)}"
          />
        </div>

        <div class="list">
          ${entries.length === 0 ? this.renderEmpty() : entries.map(entry => this.renderEntry(entry)).join('')}
        </div>
      </div>

      <div class="footer">
        <div class="footer-count">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0110 0v4"/>
          </svg>
          <span>${entries.length} password${entries.length !== 1 ? 's' : ''}</span>
        </div>
      </div>
    `;
  }

  renderEntry(entry) {
    const isExpanded = this.state.expandedEntryId === entry.id;
    const isPasswordVisible = this.state.visiblePasswords.has(entry.id);
    const details = this.state.entryDetails.get(entry.id);
    const displayUrl = entry.url ? this.formatUrl(entry.url) : '';

    return `
      <div class="entry-card ${isExpanded ? 'expanded' : ''}" data-id="${entry.id}">
        <div class="entry-header">
          <div class="entry-icon">${(entry.title || '?').charAt(0).toUpperCase()}</div>
          <div class="entry-info">
            <div class="entry-title">${this.escapeHtml(entry.title || 'Untitled')}</div>
            <div class="entry-meta">${this.escapeHtml(entry.username || '')}${displayUrl ? ' · ' + this.escapeHtml(displayUrl) : ''}</div>
          </div>
          <svg class="entry-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="6 9 12 15 18 9"/>
          </svg>
        </div>

        ${isExpanded ? this.renderEntryDetails(entry, details, isPasswordVisible) : ''}
      </div>
    `;
  }

  renderEntryDetails(entry, details, isPasswordVisible) {
    const password = details ? details.password : '';
    const maskedPassword = password ? '\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022' : '';

    return `
      <div class="entry-details">
        <div class="detail-row">
          <span class="detail-label">Username</span>
          <span class="detail-value">${this.escapeHtml(entry.username || '-')}</span>
          <div class="detail-actions">
            <button class="detail-btn" data-action="copy-username" data-value="${this.escapeHtml(entry.username || '')}" title="Copy username">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
              </svg>
            </button>
          </div>
        </div>

        <div class="detail-row">
          <span class="detail-label">Password</span>
          <span class="detail-value password ${!isPasswordVisible ? 'hidden' : ''}">${isPasswordVisible ? this.escapeHtml(password || '') : maskedPassword}</span>
          <div class="detail-actions">
            <button class="detail-btn" data-action="toggle-password" data-id="${entry.id}" title="${isPasswordVisible ? 'Hide' : 'Show'} password">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                ${isPasswordVisible
                  ? '<path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>'
                  : '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>'
                }
              </svg>
            </button>
            <button class="detail-btn" data-action="copy-password" data-value="${this.escapeHtml(password || '')}" title="Copy password">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
              </svg>
            </button>
          </div>
        </div>

        ${entry.url ? `
        <div class="detail-row">
          <span class="detail-label">Website</span>
          <span class="detail-value">${this.escapeHtml(this.formatUrl(entry.url))}</span>
          <div class="detail-actions">
            <button class="detail-btn" data-action="go-to-url" data-url="${this.escapeHtml(entry.url)}" title="Open website">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6"/>
                <polyline points="15 3 21 3 21 9"/>
                <line x1="10" y1="14" x2="21" y2="3"/>
              </svg>
            </button>
          </div>
        </div>
        ` : ''}

        <div class="quick-actions">
          <button class="action-btn primary" data-action="autofill" data-id="${entry.id}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M16 4h2a2 2 0 012 2v14a2 2 0 01-2 2H6a2 2 0 01-2-2V6a2 2 0 012-2h2"/>
              <rect x="8" y="2" width="8" height="4" rx="1" ry="1"/>
            </svg>
            Auto-fill
          </button>
          <button class="action-btn secondary" data-action="copy-both" data-id="${entry.id}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
              <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
            </svg>
            Copy Password
          </button>
        </div>
      </div>
    `;
  }

  renderEmpty() {
    if (this.state.searchQuery) {
      return `
        <div class="no-results">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="11" cy="11" r="8"/>
            <line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <p>No passwords match "${this.escapeHtml(this.state.searchQuery)}"</p>
        </div>
      `;
    }

    return `
      <div class="empty">
        <div class="empty-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0110 0v4"/>
          </svg>
        </div>
        <h3>No passwords yet</h3>
        <p>Add passwords using the desktop app</p>
      </div>
    `;
  }

  renderDisconnected() {
    return `
      <div class="disconnected-screen">
        <div class="disconnected-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/>
            <line x1="15" y1="9" x2="9" y2="15"/>
            <line x1="9" y1="9" x2="15" y2="15"/>
          </svg>
        </div>
        <h2>Not Connected</h2>
        <p>PwdVault desktop app must be running to access your passwords</p>
        <button class="btn btn-primary" id="connect-btn">Connect to Desktop App</button>
      </div>
    `;
  }

  renderError() {
    return `
      <div class="lock-screen">
        <div class="disconnected-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/>
            <line x1="12" y1="8" x2="12" y2="12"/>
            <line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
        </div>
        <h2>Error</h2>
        <p>${this.escapeHtml(this.state.error || 'Unknown error occurred')}</p>
        <button class="btn btn-primary" id="retry-btn">Try Again</button>
      </div>
    `;
  }

  attachLockScreenEvents() {
    const form = document.getElementById('unlock-form');
    if (form) {
      form.onsubmit = (e) => {
        e.preventDefault();
        const password = document.getElementById('password').value;
        if (password) {
          this.unlock(password);
        }
      };
    }
  }

  attachDisconnectedEvents() {
    const connectBtn = document.getElementById('connect-btn');
    if (connectBtn) {
      connectBtn.onclick = async () => {
        await this.sendMessage({ type: 'CONNECT' });
        // Wait a moment then retry
        setTimeout(() => this.init(), 500);
      };
    }
  }

  attachMainEvents() {
    // Search
    const search = document.getElementById('search');
    if (search) {
      search.oninput = (e) => {
        this.state.searchQuery = e.target.value;
        const entries = this.getFilteredEntries();
        const list = document.querySelector('.list');
        if (list) {
          list.innerHTML = entries.length === 0
            ? this.renderEmpty()
            : entries.map(entry => this.renderEntry(entry)).join('');
          this.attachEntryEvents();
        }
      };
    }

    // Lock button
    const lockBtn = document.getElementById('lock-btn');
    if (lockBtn) {
      lockBtn.onclick = () => this.lock();
    }

    // Generator button
    const genBtn = document.getElementById('generator-btn');
    if (genBtn) {
      genBtn.onclick = () => this.showGenerator();
    }

    // Entry items
    this.attachEntryEvents();

    // Retry button in error state
    const retryBtn = document.getElementById('retry-btn');
    if (retryBtn) {
      retryBtn.onclick = () => this.init();
    }
  }

  attachEntryEvents() {
    // Entry header clicks (expand/collapse)
    document.querySelectorAll('.entry-header').forEach(header => {
      header.onclick = () => {
        const card = header.closest('.entry-card');
        const id = card.dataset.id;
        this.toggleEntryExpansion(id);
      };
    });

    // Detail action buttons
    document.querySelectorAll('.detail-btn, .action-btn').forEach(btn => {
      btn.onclick = async (e) => {
        e.stopPropagation();
        const action = btn.dataset.action;

        switch (action) {
          case 'copy-username':
            await this.copyToClipboard(btn.dataset.value, 'Username copied!');
            break;

          case 'copy-password':
            // If password not loaded yet, get it first
            if (!btn.dataset.value && btn.dataset.id) {
              const details = await this.getEntryDetails(btn.dataset.id);
              if (details && details.password) {
                await this.copyToClipboard(details.password, 'Password copied!', true);
              }
            } else {
              await this.copyToClipboard(btn.dataset.value, 'Password copied!', true);
            }
            break;

          case 'toggle-password':
            this.togglePasswordVisibility(btn.dataset.id);
            break;

          case 'go-to-url':
            await this.goToUrl(btn.dataset.url);
            break;

          case 'autofill':
            const entry = this.state.entries.find(e => e.id === btn.dataset.id);
            if (entry) {
              await this.autofill(entry);
            }
            break;

          case 'copy-both':
            const details = await this.getEntryDetails(btn.dataset.id);
            if (details && details.password) {
              await this.copyToClipboard(details.password, 'Password copied!', true);
            }
            break;
        }
      };
    });
  }

  async showGenerator() {
    try {
      const password = await this.sendMessage({
        type: 'GENERATE_PASSWORD',
        options: { length: 16 }
      });

      if (password) {
        await this.copyToClipboard(password, 'Password generated & copied!', true);
      }
    } catch (error) {
      this.showToast('Failed to generate password');
    }
  }

  formatUrl(url) {
    try {
      const urlObj = new URL(url.startsWith('http') ? url : 'https://' + url);
      return urlObj.hostname.replace('www.', '');
    } catch {
      return url;
    }
  }

  escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
}

// Initialize app
new PopupApp();
