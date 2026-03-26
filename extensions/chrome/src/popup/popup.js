// PwdVault Popup Script

class PopupApp {
  constructor() {
    this.state = {
      status: 'loading',
      unlocked: false,
      entries: [],
      searchQuery: '',
      error: null,
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
      if (entries.error) {
        this.state.error = entries.error;
      } else {
        this.state.entries = entries || [];
      }
    } catch (error) {
      this.state.error = error.message;
    }
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
    this.render();
  }

  async autofill(entry) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab) {
      // Get full entry with password
      const fullEntry = await this.sendMessage({ type: 'GET_ENTRY', id: entry.id });
      if (fullEntry.password) {
        chrome.tabs.sendMessage(tab.id, {
          type: 'AUTOFILL',
          username: fullEntry.username,
          password: fullEntry.password,
        });
        window.close();
      }
    }
  }

  async copyToClipboard(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      return false;
    }
  }

  getFilteredEntries() {
    if (!this.state.searchQuery) return this.state.entries;

    const query = this.state.searchQuery.toLowerCase();
    return this.state.entries.filter(entry =>
      entry.title.toLowerCase().includes(query) ||
      entry.username.toLowerCase().includes(query)
    );
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
        break;
      default:
        app.innerHTML = this.renderError();
    }
  }

  renderLoading() {
    return `
      <div class="loading">
        <div class="spinner"></div>
        Loading...
      </div>
    `;
  }

  renderLockScreen() {
    return `
      <div class="lock-screen">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
          <path d="M7 11V7a5 5 0 0110 0v4"/>
        </svg>
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
          <button type="submit" class="btn btn-primary">Unlock</button>
        </form>
      </div>
    `;
  }

  renderMain() {
    const entries = this.getFilteredEntries();

    return `
      <div class="header">
        <h1>PwdVault</h1>
        <div class="header-actions">
          <button class="icon-btn" id="generator-btn" title="Password Generator">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 2v4m0 12v4M4.93 4.93l2.83 2.83m8.48 8.48l2.83 2.83M2 12h4m12 0h4M4.93 19.07l2.83-2.83m8.48-8.48l2.83-2.83"/>
            </svg>
          </button>
          <button class="icon-btn" id="lock-btn" title="Lock Vault">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
              <path d="M7 11V7a5 5 0 0110 0v4"/>
            </svg>
          </button>
        </div>
      </div>

      <div class="content">
        <input
          type="text"
          class="search"
          id="search"
          placeholder="Search passwords..."
          value="${this.escapeHtml(this.state.searchQuery)}"
        />

        <div class="list">
          ${entries.length === 0 ? this.renderEmpty() : entries.map(entry => this.renderEntry(entry)).join('')}
        </div>
      </div>

      <div class="footer">
        ${entries.length} password${entries.length !== 1 ? 's' : ''}
      </div>
    `;
  }

  renderEntry(entry) {
    return `
      <div class="item" data-id="${entry.id}">
        <div class="icon">${entry.title.charAt(0).toUpperCase()}</div>
        <div class="info">
          <h3>${this.escapeHtml(entry.title)}</h3>
          <p>${this.escapeHtml(entry.username)}</p>
        </div>
      </div>
    `;
  }

  renderEmpty() {
    return `
      <div class="empty">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
          <path d="M7 11V7a5 5 0 0110 0v4"/>
        </svg>
        <p>No passwords found</p>
      </div>
    `;
  }

  renderDisconnected() {
    return `
      <div class="lock-screen">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color: #f87171;">
          <circle cx="12" cy="12" r="10"/>
          <line x1="15" y1="9" x2="9" y2="15"/>
          <line x1="9" y1="9" x2="15" y2="15"/>
        </svg>
        <h2>Not Connected</h2>
        <p>PwdVault desktop app is not running</p>
        <button class="btn btn-primary" id="connect-btn">Connect</button>
      </div>
    `;
  }

  renderError() {
    return `
      <div class="status error">
        <p>${this.escapeHtml(this.state.error || 'Unknown error')}</p>
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

  attachMainEvents() {
    // Search
    const search = document.getElementById('search');
    if (search) {
      search.oninput = (e) => {
        this.state.searchQuery = e.target.value;
        document.querySelector('.list').innerHTML = this.getFilteredEntries().length === 0
          ? this.renderEmpty()
          : this.getFilteredEntries().map(entry => this.renderEntry(entry)).join('');
        this.attachEntryEvents();
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
  }

  attachEntryEvents() {
    document.querySelectorAll('.item').forEach(item => {
      item.onclick = () => {
        const id = item.dataset.id;
        const entry = this.state.entries.find(e => e.id === id);
        if (entry) {
          this.autofill(entry);
        }
      };
    });
  }

  async showGenerator() {
    const password = await this.sendMessage({
      type: 'GENERATE_PASSWORD',
      options: { length: 16 }
    });

    if (password) {
      await this.copyToClipboard(password);
      alert(`Password copied to clipboard:\n\n${password}`);
    }
  }

  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text || '';
    return div.innerHTML;
  }
}

// Initialize app
new PopupApp();