// PwdVault Content Script
// Detects login forms and handles auto-fill

(function() {
  'use strict';

  // ============================================================================
  // Form Detection
  // ============================================================================

  const PASSWORD_INPUT_TYPES = ['password', 'text', 'email'];
  const USERNAME_INPUT_TYPES = ['text', 'email', 'tel'];
  const USERNAME_PATTERNS = [
    /user/i, /login/i, /email/i, /e-mail/i, /account/i,
    /identifier/i, /username/i, /name$/i, /^log$/i
  ];
  const PASSWORD_PATTERNS = [
    /pass/i, /pwd/i, /secret/i
  ];
  const SUBMIT_PATTERNS = [
    /login/i, /sign.?in/i, /log.?in/i, /submit/i, /enter/i,
    /continue/i, /next/i, /auth/i
  ];

  function findLoginForm() {
    const passwordInputs = Array.from(document.querySelectorAll('input[type="password"]'));

    if (passwordInputs.length === 0) {
      return null;
    }

    // Try to find the associated username field
    for (const passwordInput of passwordInputs) {
      const form = passwordInput.closest('form');
      const container = form || passwordInput.closest('div, section, article') || document.body;

      // Look for username field
      const textInputs = Array.from(container.querySelectorAll('input'))
        .filter(input => USERNAME_INPUT_TYPES.includes(input.type) && input !== passwordInput);

      // Sort by position (above the password field)
      const passwordRect = passwordInput.getBoundingClientRect();

      const usernameCandidates = textInputs.filter(input => {
        const rect = input.getBoundingClientRect();
        return rect.top < passwordRect.top + 50; // Within 50px above
      });

      // Score by patterns
      let usernameField = null;
      let bestScore = -1;

      for (const input of usernameCandidates) {
        const score = scoreInput(input, USERNAME_PATTERNS);
        if (score > bestScore) {
          bestScore = score;
          usernameField = input;
        }
      }

      // Find submit button
      const submitButton = findSubmitButton(container);

      return {
        passwordField: passwordInput,
        usernameField,
        submitButton,
        form
      };
    }

    return null;
  }

  function scoreInput(input, patterns) {
    let score = 0;

    const name = input.name || '';
    const id = input.id || '';
    const placeholder = input.placeholder || '';
    const ariaLabel = input.getAttribute('aria-label') || '';

    const text = `${name} ${id} ${placeholder} ${ariaLabel}`.toLowerCase();

    for (const pattern of patterns) {
      if (pattern.test(text)) {
        score += 10;
      }
    }

    // Bonus for autocomplete attributes
    const autocomplete = input.getAttribute('autocomplete') || '';
    if (patterns.some(p => p.test(autocomplete))) {
      score += 5;
    }

    return score;
  }

  function findSubmitButton(container) {
    const buttons = Array.from(container.querySelectorAll('button, input[type="submit"], input[type="button"]'));

    for (const button of buttons) {
      const text = (button.textContent || button.value || '').toLowerCase();
      for (const pattern of SUBMIT_PATTERNS) {
        if (pattern.test(text)) {
          return button;
        }
      }
    }

    return null;
  }

  // ============================================================================
  // Auto-fill
  // ============================================================================

  function fillField(field, value) {
    if (!field) return false;

    // Focus the field
    field.focus();

    // Clear existing value
    field.value = '';

    // Set new value
    field.value = value;

    // Dispatch events to trigger validation
    field.dispatchEvent(new Event('input', { bubbles: true }));
    field.dispatchEvent(new Event('change', { bubbles: true }));
    field.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true }));
    field.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true }));

    return true;
  }

  function autofillLogin(username, password) {
    const loginForm = findLoginForm();

    if (!loginForm) {
      showNotification('No login form detected on this page', 'error');
      return false;
    }

    // Fill username
    if (loginForm.usernameField) {
      fillField(loginForm.usernameField, username);
    }

    // Fill password
    fillField(loginForm.passwordField, password);

    showNotification('Credentials filled successfully', 'success');

    // Focus submit button if available
    if (loginForm.submitButton) {
      loginForm.submitButton.focus();
    }

    return true;
  }

  function insertPassword(password) {
    const activeElement = document.activeElement;

    if (activeElement && activeElement.tagName === 'INPUT') {
      fillField(activeElement, password);
      showNotification('Password inserted', 'success');
      return true;
    }

    showNotification('Please focus on a password field first', 'error');
    return false;
  }

  // ============================================================================
  // UI Overlay
  // ============================================================================

  let overlay = null;

  function createOverlay() {
    if (overlay) return overlay;

    overlay = document.createElement('div');
    overlay.id = 'pwdvault-overlay';
    overlay.innerHTML = `
      <style>
        #pwdvault-overlay {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: rgba(0, 0, 0, 0.5);
          display: flex;
          align-items: flex-start;
          justify-content: center;
          padding-top: 100px;
          z-index: 2147483647;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }
        #pwdvault-modal {
          background: #1e1e2e;
          border-radius: 12px;
          padding: 20px;
          min-width: 320px;
          max-width: 400px;
          box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
          color: #e0e0e0;
        }
        #pwdvault-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 16px;
        }
        #pwdvault-header h3 {
          font-size: 16px;
          font-weight: 600;
          margin: 0;
        }
        #pwdvault-close {
          background: none;
          border: none;
          color: #888;
          font-size: 20px;
          cursor: pointer;
          padding: 4px;
        }
        #pwdvault-close:hover {
          color: #fff;
        }
        #pwdvault-search {
          width: 100%;
          padding: 10px 12px;
          border: 1px solid #333;
          border-radius: 8px;
          background: #262637;
          color: #fff;
          font-size: 14px;
          margin-bottom: 12px;
          box-sizing: border-box;
        }
        #pwdvault-search:focus {
          outline: none;
          border-color: #6366f1;
        }
        #pwdvault-list {
          max-height: 280px;
          overflow-y: auto;
        }
        .pwdvault-item {
          display: flex;
          align-items: center;
          padding: 12px;
          border-radius: 8px;
          cursor: pointer;
          transition: background 0.2s;
        }
        .pwdvault-item:hover {
          background: #262637;
        }
        .pwdvault-icon {
          width: 36px;
          height: 36px;
          border-radius: 8px;
          background: #6366f1;
          display: flex;
          align-items: center;
          justify-content: center;
          font-weight: 600;
          color: #fff;
          margin-right: 12px;
          text-transform: uppercase;
        }
        .pwdvault-info h4 {
          font-size: 14px;
          font-weight: 500;
          margin: 0 0 4px 0;
        }
        .pwdvault-info p {
          font-size: 12px;
          color: #888;
          margin: 0;
        }
        #pwdvault-empty {
          text-align: center;
          padding: 32px 16px;
          color: #666;
        }
        #pwdvault-status {
          text-align: center;
          padding: 32px 16px;
        }
        #pwdvault-status.error {
          color: #f87171;
        }
      </style>
      <div id="pwdvault-modal">
        <div id="pwdvault-header">
          <h3>PwdVault</h3>
          <button id="pwdvault-close">×</button>
        </div>
        <input id="pwdvault-search" type="text" placeholder="Search passwords...">
        <div id="pwdvault-content"></div>
      </div>
    `;

    overlay.querySelector('#pwdvault-close').addEventListener('click', hideOverlay);
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) hideOverlay();
    });

    return overlay;
  }

  function showOverlay() {
    const overlayEl = createOverlay();
    document.body.appendChild(overlayEl);
    loadEntries();
    overlayEl.querySelector('#pwdvault-search').focus();
  }

  function hideOverlay() {
    if (overlay && overlay.parentNode) {
      overlay.parentNode.removeChild(overlay);
    }
  }

  async function loadEntries() {
    const content = overlay.querySelector('#pwdvault-content');

    try {
      const response = await chrome.runtime.sendMessage({
        type: 'GET_ENTRIES_FOR_URL',
        url: window.location.href
      });

      if (response.error) {
        content.innerHTML = `<div id="pwdvault-status" class="error">${response.error}</div>`;
        return;
      }

      renderEntries(response);
    } catch (error) {
      content.innerHTML = `<div id="pwdvault-status" class="error">Failed to load entries: ${error.message}</div>`;
    }
  }

  function renderEntries(entries) {
    const content = overlay.querySelector('#pwdvault-content');

    if (!entries || entries.length === 0) {
      content.innerHTML = `<div id="pwdvault-empty">No passwords found for this site</div>`;
      return;
    }

    const list = document.createElement('div');
    list.id = 'pwdvault-list';

    entries.forEach(entry => {
      const item = document.createElement('div');
      item.className = 'pwdvault-item';
      item.innerHTML = `
        <div class="pwdvault-icon">${entry.title.charAt(0)}</div>
        <div class="pwdvault-info">
          <h4>${escapeHtml(entry.title)}</h4>
          <p>${escapeHtml(entry.username)}</p>
        </div>
      `;

      item.addEventListener('click', () => selectEntry(entry.id));
      list.appendChild(item);
    });

    content.innerHTML = '';
    content.appendChild(list);

    // Setup search
    const searchInput = overlay.querySelector('#pwdvault-search');
    searchInput.oninput = () => filterEntries(entries, searchInput.value);
  }

  function filterEntries(entries, query) {
    const lowerQuery = query.toLowerCase();
    const filtered = entries.filter(entry =>
      entry.title.toLowerCase().includes(lowerQuery) ||
      entry.username.toLowerCase().includes(lowerQuery)
    );
    renderEntries(filtered);
  }

  async function selectEntry(id) {
    try {
      const entry = await chrome.runtime.sendMessage({
        type: 'GET_ENTRY',
        id
      });

      if (entry.error) {
        showNotification(entry.error, 'error');
        return;
      }

      hideOverlay();
      autofillLogin(entry.username, entry.password);
    } catch (error) {
      showNotification('Failed to get entry: ' + error.message, 'error');
    }
  }

  // ============================================================================
  // Notifications
  // ============================================================================

  function showNotification(message, type = 'info') {
    const existing = document.getElementById('pwdvault-notification');
    if (existing) existing.remove();

    const notification = document.createElement('div');
    notification.id = 'pwdvault-notification';
    notification.style.cssText = `
      position: fixed;
      bottom: 20px;
      right: 20px;
      padding: 12px 20px;
      border-radius: 8px;
      font-size: 14px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      z-index: 2147483647;
      animation: slideIn 0.3s ease-out;
      background: ${type === 'error' ? '#dc2626' : type === 'success' ? '#16a34a' : '#6366f1'};
      color: white;
    `;
    notification.textContent = message;

    const style = document.createElement('style');
    style.textContent = `
      @keyframes slideIn {
        from { transform: translateY(20px); opacity: 0; }
        to { transform: translateY(0); opacity: 1; }
      }
    `;
    document.head.appendChild(style);
    document.body.appendChild(notification);

    setTimeout(() => notification.remove(), 3000);
  }

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  // ============================================================================
  // Floating Button
  // ============================================================================

  let floatingButton = null;

  function createFloatingButton() {
    if (floatingButton) return;

    const loginForm = findLoginForm();
    if (!loginForm || !loginForm.passwordField) return;

    floatingButton = document.createElement('div');
    floatingButton.id = 'pwdvault-floating-btn';
    floatingButton.innerHTML = `
      <style>
        #pwdvault-floating-btn {
          position: fixed;
          width: 40px;
          height: 40px;
          background: #6366f1;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          cursor: pointer;
          box-shadow: 0 2px 8px rgba(99, 102, 241, 0.4);
          z-index: 2147483646;
          transition: transform 0.2s;
        }
        #pwdvault-floating-btn:hover {
          transform: scale(1.1);
        }
        #pwdvault-floating-btn svg {
          width: 20px;
          height: 20px;
          fill: white;
        }
      </style>
      <svg viewBox="0 0 24 24">
        <path d="M12 2C9.24 2 7 4.24 7 7v2H6c-1.1 0-2 .9-2 2v9c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2v-9c0-1.1-.9-2-2-2h-1V7c0-2.76-2.24-5-5-5zm0 2c1.66 0 3 1.34 3 3v2H9V7c0-1.66 1.34-3 3-3zm0 10c1.1 0 2 .9 2 2s-.9 2-2 2-2-.9-2-2 .9-2 2-2z"/>
      </svg>
    `;

    // Position near password field
    const rect = loginForm.passwordField.getBoundingClientRect();
    floatingButton.style.top = `${window.scrollY + rect.top - 50}px`;
    floatingButton.style.right = '20px';

    floatingButton.addEventListener('click', (e) => {
      e.preventDefault();
      showOverlay();
    });

    document.body.appendChild(floatingButton);
  }

  // ============================================================================
  // Message Handling
  // ============================================================================

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    switch (message.type) {
      case 'AUTOFILL':
        autofillLogin(message.username, message.password);
        sendResponse({ success: true });
        break;

      case 'INSERT_PASSWORD':
        insertPassword(message.password);
        sendResponse({ success: true });
        break;

      case 'SHOW_POPUP':
        showOverlay();
        sendResponse({ success: true });
        break;

      case 'DETECT_FORM':
        const form = findLoginForm();
        sendResponse({ hasForm: !!form });
        break;

      default:
        sendResponse({ error: 'Unknown message type' });
    }
    return true;
  });

  // ============================================================================
  // Initialization
  // ============================================================================

  // Wait for page to load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      setTimeout(createFloatingButton, 500);
    });
  } else {
    setTimeout(createFloatingButton, 500);
  }

  // Re-check for forms on dynamic page changes
  const observer = new MutationObserver(() => {
    if (!floatingButton) {
      createFloatingButton();
    }
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });

})();