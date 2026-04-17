// PwdVault Popup Script - Enhanced with Groups, Generator UI, and Theme Switching
import Fuse from './fuse.min.mjs';

class PopupApp {
  constructor() {
    this.state = {
      status: 'loading',
      unlocked: false,
      entries: [],
      groups: [],
      selectedGroupId: null,
      entryDetails: new Map(),
      searchQuery: '',
      error: null,
      expandedEntryId: null,
      visiblePasswords: new Set(),
      theme: 'classic',
      // Generator state
      generatedPassword: '',
      generatorOptions: {
        length: 16,
        includeUppercase: true,
        includeLowercase: true,
        includeNumbers: true,
        includeSymbols: true,
      },
      generatorCopied: false,
    };

    this.loadTheme();
    this.init();
  }

  // === Theme Management ===

  loadTheme() {
    try {
      const saved = localStorage.getItem('pwdvault-theme');
      if (saved && ['classic', 'cyber', 'hybrid'].includes(saved)) {
        this.state.theme = saved;
      }
    } catch {}
    this.applyTheme();
  }

  setTheme(theme) {
    this.state.theme = theme;
    try {
      localStorage.setItem('pwdvault-theme', theme);
    } catch {}
    this.applyTheme();
    // Re-render only header to update active dot (avoid full re-render)
    const switcher = document.querySelector('.theme-switcher');
    if (switcher) {
      switcher.querySelectorAll('.theme-dot').forEach(dot => {
        dot.classList.toggle('active', dot.dataset.theme === theme);
      });
    }
  }

  applyTheme() {
    document.documentElement.setAttribute('data-theme', this.state.theme);
    // Smooth transition
    document.documentElement.classList.add('theme-transitioning');
    setTimeout(() => {
      document.documentElement.classList.remove('theme-transitioning');
    }, 300);
  }

  // === Init ===

  async init() {
    try {
      const status = await this.sendMessage({ type: 'GET_STATUS' });

      if (status.unlocked) {
        this.state.status = 'unlocked';
        this.state.unlocked = true;
        await Promise.all([this.loadEntries(), this.loadGroups()]);
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

  // === Data Loading ===

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

  async loadGroups() {
    try {
      const groups = await this.sendMessage({ type: 'GET_GROUPS' });
      if (groups && !groups.error) {
        this.state.groups = groups || [];
      }
    } catch {
      // Groups not available — non-critical
      this.state.groups = [];
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

  // === Vault Actions ===

  async unlock(password) {
    this.state.status = 'loading';
    this.render();

    try {
      const result = await this.sendMessage({ type: 'UNLOCK_VAULT', password });
      if (result === true) {
        this.state.unlocked = true;
        this.state.status = 'unlocked';
        this.state.error = null;
        await Promise.all([this.loadEntries(), this.loadGroups()]);
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
    this.state.groups = [];
    this.state.selectedGroupId = null;
    this.state.entryDetails.clear();
    this.state.expandedEntryId = null;
    this.state.visiblePasswords.clear();
    this.render();
  }

  // === Clipboard ===

  async copyToClipboard(text, label = 'Copied!', autoClear = false) {
    try {
      await navigator.clipboard.writeText(text);

      if (autoClear) {
        setTimeout(async () => {
          try {
            const current = await navigator.clipboard.readText();
            if (current === text) {
              await navigator.clipboard.writeText('');
            }
          } catch {}
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

  // === Auto-fill ===

  async autofill(entry) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab) {
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

  // === Password Strength (simplified) ===

  getPasswordStrength(password) {
    if (!password) return { score: 0, label: '', color: 'var(--color-text-muted)' };

    let score = 0;
    if (password.length >= 8) score += 15;
    if (password.length >= 12) score += 15;
    if (password.length >= 16) score += 10;
    if (password.length >= 24) score += 10;

    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasDigit = /[0-9]/.test(password);
    const hasSymbol = /[^a-zA-Z0-9]/.test(password);

    const types = [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length;
    score += types * 12;

    // Unique characters bonus
    const unique = new Set(password).size;
    score += Math.min(unique * 2, 14);

    score = Math.min(score, 100);

    let label, color;
    if (score < 25) { label = 'Weak'; color = 'var(--color-danger)'; }
    else if (score < 50) { label = 'Fair'; color = 'var(--color-warning)'; }
    else if (score < 75) { label = 'Good'; color = 'var(--color-primary)'; }
    else { label = 'Strong'; color = 'var(--color-success)'; }

    return { score, label, color };
  }

  // === Filtering ===

  getFilteredEntries() {
    let entries = this.state.entries;

    if (this.state.selectedGroupId) {
      entries = entries.filter(e => e.group_id === this.state.selectedGroupId);
    }

    if (!this.state.searchQuery || !this.state.searchQuery.trim()) return entries;

    const fuse = new Fuse(entries, {
      keys: [
        { name: 'title', weight: 0.4 },
        { name: 'username', weight: 0.3 },
        { name: 'url', weight: 0.2 },
        { name: 'tags', weight: 0.1 },
      ],
      threshold: 0.3,
      includeScore: true,
      ignoreLocation: true,
    });

    return fuse.search(this.state.searchQuery).map(r => r.item);
  }

  // === UI State ===

  showToast(message) {
    const toast = document.getElementById('toast');
    const messageEl = document.getElementById('toast-message');
    messageEl.textContent = message;
    toast.classList.add('show');
    setTimeout(() => {
      toast.classList.remove('show');
    }, 2000);
  }

  toggleEntryExpansion(entryId) {
    if (this.state.expandedEntryId === entryId) {
      this.state.expandedEntryId = null;
    } else {
      this.state.expandedEntryId = entryId;
      this.state.visiblePasswords.clear();
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

  // === Render Router ===

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
      case 'creating':
        app.innerHTML = this.renderCreateForm();
        this.attachCreateFormEvents();
        break;
      case 'generator':
        app.innerHTML = this.renderGenerator();
        this.attachGeneratorEvents();
        if (!this.state.generatedPassword) {
          this.handleGenerate();
        }
        break;
      case 'disconnected':
        app.innerHTML = this.renderDisconnected();
        this.attachDisconnectedEvents();
        break;
      default:
        app.innerHTML = this.renderError();
    }
  }

  // === Render: Loading ===

  renderLoading() {
    return `
      <div class="loading">
        <div class="spinner"></div>
        <span>Loading...</span>
      </div>
    `;
  }

  // === Render: Lock Screen ===

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
            <input type="password" id="password" class="form-input" placeholder="Enter password" autofocus />
          </div>
          <button type="submit" class="btn btn-primary">Unlock Vault</button>
        </form>
      </div>
    `;
  }

  // === Render: Main (with groups + theme switcher) ===

  renderMain() {
    const entries = this.getFilteredEntries();
    const groups = this.state.groups;
    const theme = this.state.theme;

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
          <div class="theme-switcher">
            <button class="theme-dot theme-dot-classic ${theme === 'classic' ? 'active' : ''}" data-theme="classic" title="Classic"></button>
            <button class="theme-dot theme-dot-cyber ${theme === 'cyber' ? 'active' : ''}" data-theme="cyber" title="Cyber"></button>
            <button class="theme-dot theme-dot-hybrid ${theme === 'hybrid' ? 'active' : ''}" data-theme="hybrid" title="Hybrid"></button>
          </div>
          <button class="icon-btn" id="add-btn" title="Add Password">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="12" y1="5" x2="12" y2="19"/>
              <line x1="5" y1="12" x2="19" y2="12"/>
            </svg>
          </button>
          <button class="icon-btn" id="generator-btn" title="Password Generator">
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
          <input type="text" class="search" id="search" placeholder="Search passwords..."
            value="${this.escapeHtml(this.state.searchQuery)}" />
        </div>

        ${groups.length > 0 ? `
        <div class="group-tabs">
          <div class="group-tabs-scroll">
            <button class="group-tab ${!this.state.selectedGroupId ? 'active' : ''}" data-group-id="">All</button>
            ${groups.map(g => `
              <button class="group-tab ${this.state.selectedGroupId === g.id ? 'active' : ''}" data-group-id="${this.escapeHtml(g.id)}">${this.escapeHtml(g.name)}</button>
            `).join('')}
          </div>
        </div>
        ` : ''}

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

  // === Render: Create Form (with group selector) ===

  renderCreateForm() {
    const groups = this.state.groups;

    return `
      <div class="header">
        <div class="header-brand">
          <button class="icon-btn" id="back-btn" title="Back">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="15 18 9 12 15 6"/>
            </svg>
          </button>
          <h1>New Password</h1>
        </div>
      </div>

      <div class="content">
        ${this.state.error ? `<div class="error-message">${this.escapeHtml(this.state.error)}</div>` : ''}
        <form id="create-form" class="create-form">
          <div class="form-group">
            <label for="entry-title">Title *</label>
            <input type="text" id="entry-title" class="form-input" placeholder="e.g. GitHub" required autofocus />
          </div>
          <div class="form-group">
            <label for="entry-username">Username / Email *</label>
            <input type="text" id="entry-username" class="form-input" placeholder="e.g. user@example.com" required />
          </div>
          <div class="form-group">
            <label for="entry-password">Password *</label>
            <div class="password-input-group">
              <input type="password" id="entry-password" class="form-input" placeholder="Enter password" required />
              <button type="button" class="icon-btn-sm" id="toggle-pw-visibility" title="Show/Hide">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                  <circle cx="12" cy="12" r="3"/>
                </svg>
              </button>
              <button type="button" class="icon-btn-sm" id="gen-pw-btn" title="Generate Password">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M12 2v4m0 12v4M4.93 4.93l2.83 2.83m8.48 8.48l2.83 2.83M2 12h4m12 0h4M4.93 19.07l2.83-2.83m8.48-8.48l2.83-2.83"/>
                </svg>
              </button>
            </div>
          </div>
          <div class="form-group">
            <label for="entry-url">Website URL</label>
            <input type="text" id="entry-url" class="form-input" placeholder="e.g. https://github.com" />
          </div>
          ${groups.length > 0 ? `
          <div class="form-group">
            <label for="entry-group">Group</label>
            <select id="entry-group" class="form-select">
              <option value="">No group</option>
              ${groups.map(g => `<option value="${this.escapeHtml(g.id)}">${this.escapeHtml(g.name)}</option>`).join('')}
            </select>
          </div>
          ` : ''}
          <div class="form-group">
            <label for="entry-notes">Notes</label>
            <textarea id="entry-notes" class="form-input form-textarea" placeholder="Optional notes..." rows="2"></textarea>
          </div>
          <button type="submit" class="btn btn-primary" style="width:100%;margin-top:12px;">Save Password</button>
        </form>
      </div>
    `;
  }

  // === Render: Generator Screen ===

  renderGenerator() {
    const opts = this.state.generatorOptions;
    const password = this.state.generatedPassword;
    const strength = this.getPasswordStrength(password);
    const copied = this.state.generatorCopied;

    return `
      <div class="header">
        <div class="header-brand">
          <button class="icon-btn" id="back-btn" title="Back">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="15 18 9 12 15 6"/>
            </svg>
          </button>
          <h1>Password Generator</h1>
        </div>
      </div>

      <div class="generator-content">
        <div class="password-preview" id="password-preview">
          ${password ? this.escapeHtml(password) : 'Generating...'}
        </div>

        <div class="strength-meter">
          <div class="strength-bar">
            <div class="strength-bar-fill" style="width: ${strength.score}%; background-color: ${strength.color}"></div>
          </div>
          <span class="strength-label" style="color: ${strength.color}">${strength.label}</span>
        </div>

        <div class="option-group">
          <div class="option-row">
            <label>Length: ${opts.length}</label>
          </div>
          <div class="length-control">
            <input type="range" id="gen-length" min="8" max="64" value="${opts.length}" />
          </div>
        </div>

        <div class="option-group">
          <div class="checkbox-wrapper">
            <input type="checkbox" id="gen-uppercase" ${opts.includeUppercase ? 'checked' : ''} />
            <label for="gen-uppercase">Uppercase (A-Z)</label>
          </div>
          <div class="checkbox-wrapper">
            <input type="checkbox" id="gen-lowercase" ${opts.includeLowercase ? 'checked' : ''} />
            <label for="gen-lowercase">Lowercase (a-z)</label>
          </div>
          <div class="checkbox-wrapper">
            <input type="checkbox" id="gen-numbers" ${opts.includeNumbers ? 'checked' : ''} />
            <label for="gen-numbers">Numbers (0-9)</label>
          </div>
          <div class="checkbox-wrapper">
            <input type="checkbox" id="gen-symbols" ${opts.includeSymbols ? 'checked' : ''} />
            <label for="gen-symbols">Symbols (!@#$...)</label>
          </div>
        </div>

        <button class="btn btn-secondary" id="gen-regenerate">Generate New Password</button>
      </div>

      <div class="generator-actions">
        <button class="btn btn-primary" id="gen-copy">
          ${copied ? 'Copied!' : 'Copy to Clipboard'}
        </button>
      </div>
    `;
  }

  // === Render: Entry Card ===

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
        <p>Click + to add a new password</p>
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

  // === Event Attachers ===

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
        setTimeout(() => this.init(), 500);
      };
    }
  }

  attachMainEvents() {
    // Theme dots
    document.querySelectorAll('.theme-dot').forEach(dot => {
      dot.onclick = () => this.setTheme(dot.dataset.theme);
    });

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

    // Group tabs
    document.querySelectorAll('.group-tab').forEach(tab => {
      tab.onclick = () => {
        this.state.selectedGroupId = tab.dataset.groupId || null;
        const entries = this.getFilteredEntries();
        const list = document.querySelector('.list');
        if (list) {
          list.innerHTML = entries.length === 0
            ? this.renderEmpty()
            : entries.map(entry => this.renderEntry(entry)).join('');
          this.attachEntryEvents();
        }
        // Update active tab
        document.querySelectorAll('.group-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        // Update footer count
        const footer = document.querySelector('.footer-count span');
        if (footer) {
          footer.textContent = `${entries.length} password${entries.length !== 1 ? 's' : ''}`;
        }
      };
    });

    // Add button
    const addBtn = document.getElementById('add-btn');
    if (addBtn) {
      addBtn.onclick = () => {
        this.state.status = 'creating';
        this.state.error = null;
        this.render();
      };
    }

    // Lock button
    const lockBtn = document.getElementById('lock-btn');
    if (lockBtn) {
      lockBtn.onclick = () => this.lock();
    }

    // Generator button — now opens generator screen
    const genBtn = document.getElementById('generator-btn');
    if (genBtn) {
      genBtn.onclick = () => {
        this.state.status = 'generator';
        this.state.generatedPassword = '';
        this.state.generatorCopied = false;
        this.render();
      };
    }

    // Entry items
    this.attachEntryEvents();
  }

  attachCreateFormEvents() {
    // Back button
    const backBtn = document.getElementById('back-btn');
    if (backBtn) {
      backBtn.onclick = () => {
        this.state.status = 'unlocked';
        this.state.error = null;
        this.render();
      };
    }

    // Toggle password visibility
    const togglePwBtn = document.getElementById('toggle-pw-visibility');
    if (togglePwBtn) {
      togglePwBtn.onclick = () => {
        const pwInput = document.getElementById('entry-password');
        pwInput.type = pwInput.type === 'password' ? 'text' : 'password';
      };
    }

    // Generate password in form
    const genPwBtn = document.getElementById('gen-pw-btn');
    if (genPwBtn) {
      genPwBtn.onclick = async () => {
        try {
          const password = await this.sendMessage({
            type: 'GENERATE_PASSWORD',
            options: { length: 20 }
          });
          if (password) {
            const pwInput = document.getElementById('entry-password');
            pwInput.value = password;
            pwInput.type = 'text';
          }
        } catch {
          this.showToast('Failed to generate password');
        }
      };
    }

    // Submit form
    const form = document.getElementById('create-form');
    if (form) {
      form.onsubmit = async (e) => {
        e.preventDefault();

        const title = document.getElementById('entry-title').value.trim();
        const username = document.getElementById('entry-username').value.trim();
        const password = document.getElementById('entry-password').value;
        const url = document.getElementById('entry-url').value.trim();
        const notes = document.getElementById('entry-notes').value.trim();
        const groupId = document.getElementById('entry-group')?.value || null;

        if (!title || !username || !password) {
          this.state.error = 'Title, username, and password are required';
          this.render();
          return;
        }

        try {
          const result = await this.sendMessage({
            type: 'CREATE_ENTRY',
            entry: {
              title,
              username,
              password,
              url: url || null,
              notes: notes || null,
              tags: [],
              group_id: groupId,
            },
          });

          if (result && result.error) {
            this.state.error = result.error;
            this.render();
            return;
          }

          this.state.status = 'unlocked';
          this.state.error = null;
          await Promise.all([this.loadEntries(), this.loadGroups()]);
          this.render();
          this.showToast('Password saved!');
        } catch (error) {
          this.state.error = error.message;
          this.render();
        }
      };
    }
  }

  attachGeneratorEvents() {
    // Back button
    const backBtn = document.getElementById('back-btn');
    if (backBtn) {
      backBtn.onclick = () => {
        this.state.status = 'unlocked';
        this.state.generatedPassword = '';
        this.render();
      };
    }

    // Length slider
    const lengthSlider = document.getElementById('gen-length');
    if (lengthSlider) {
      lengthSlider.oninput = (e) => {
        this.state.generatorOptions.length = parseInt(e.target.value);
        this.handleGenerate();
      };
    }

    // Checkboxes
    const checkboxes = [
      { id: 'gen-uppercase', key: 'includeUppercase' },
      { id: 'gen-lowercase', key: 'includeLowercase' },
      { id: 'gen-numbers', key: 'includeNumbers' },
      { id: 'gen-symbols', key: 'includeSymbols' },
    ];

    checkboxes.forEach(({ id, key }) => {
      const cb = document.getElementById(id);
      if (cb) {
        cb.onchange = (e) => {
          this.state.generatorOptions[key] = e.target.checked;
          this.handleGenerate();
        };
      }
    });

    // Regenerate button
    const regenBtn = document.getElementById('gen-regenerate');
    if (regenBtn) {
      regenBtn.onclick = () => this.handleGenerate();
    }

    // Copy button
    const copyBtn = document.getElementById('gen-copy');
    if (copyBtn) {
      copyBtn.onclick = async () => {
        if (this.state.generatedPassword) {
          await this.copyToClipboard(this.state.generatedPassword, 'Password copied!', true);
          this.state.generatorCopied = true;
          copyBtn.textContent = 'Copied!';
          setTimeout(() => {
            this.state.generatorCopied = false;
            if (copyBtn) copyBtn.textContent = 'Copy to Clipboard';
          }, 2000);
        }
      };
    }
  }

  async handleGenerate() {
    try {
      const opts = this.state.generatorOptions;
      const password = await this.sendMessage({
        type: 'GENERATE_PASSWORD',
        options: {
          length: opts.length,
          uppercase: opts.includeUppercase,
          lowercase: opts.includeLowercase,
          numbers: opts.includeNumbers,
          symbols: opts.includeSymbols,
        },
      });

      if (password) {
        this.state.generatedPassword = password;
        this.state.generatorCopied = false;

        // Update preview and strength meter without full re-render
        const preview = document.getElementById('password-preview');
        if (preview) {
          preview.textContent = password;
        }

        const strength = this.getPasswordStrength(password);
        const barFill = document.querySelector('.strength-bar-fill');
        if (barFill) {
          barFill.style.width = `${strength.score}%`;
          barFill.style.backgroundColor = strength.color;
        }

        const label = document.querySelector('.strength-label');
        if (label) {
          label.textContent = strength.label;
          label.style.color = strength.color;
        }

        // Update length label
        const lengthLabel = document.querySelector('.option-row label');
        if (lengthLabel) {
          lengthLabel.textContent = `Length: ${opts.length}`;
        }
      }
    } catch {
      this.showToast('Failed to generate password');
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

  // === Utilities ===

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
