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
    /identifier/i, /username/i, /name$/i, /^log$/i, /auth/i
  ];
  const PASSWORD_PATTERNS = [
    /pass/i, /pwd/i, /secret/i, /credential/i
  ];
  const SUBMIT_PATTERNS = [
    /login/i, /sign.?in/i, /log.?in/i, /submit/i, /enter/i,
    /continue/i, /next/i, /auth/i, /go/i
  ];
  // Patterns for registration/change password forms
  const REGISTER_PATTERNS = [
    /register/i, /sign.?up/i, /create/i, /join/i, /new.?account/i
  ];
  const CHANGE_PASSWORD_PATTERNS = [
    /change.?pass/i, /update.?pass/i, /new.?pass/i, /reset.?pass/i,
    /current.?pass/i, /old.?pass/i, /confirm.?pass/i
  ];

  // Form types
  const FORM_TYPES = {
    LOGIN: 'login',
    REGISTER: 'register',
    CHANGE_PASSWORD: 'changePassword',
    UNKNOWN: 'unknown'
  };

  function detectFormType(container) {
    const text = container.textContent || '';
    const formAction = (container.getAttribute('action') || '').toLowerCase();

    if (REGISTER_PATTERNS.some(p => p.test(text) || p.test(formAction))) {
      return FORM_TYPES.REGISTER;
    }
    if (CHANGE_PASSWORD_PATTERNS.some(p => p.test(text) || p.test(formAction))) {
      return FORM_TYPES.CHANGE_PASSWORD;
    }
    return FORM_TYPES.LOGIN;
  }

  function findLoginForm() {
    const passwordInputs = Array.from(document.querySelectorAll('input[type="password"]'));

    if (passwordInputs.length === 0) {
      return null;
    }

    // Try to find the associated username field
    for (const passwordInput of passwordInputs) {
      const form = passwordInput.closest('form');
      const container = form || passwordInput.closest('div, section, article') || document.body;

      // Detect form type
      const formType = detectFormType(container);

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
        form,
        formType,
        container
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
    const label = findLabelForInput(input);
    const dataTestid = input.getAttribute('data-testid') || '';

    const text = `${name} ${id} ${placeholder} ${ariaLabel} ${label} ${dataTestid}`.toLowerCase();

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

    // Bonus for specific autocomplete values
    if (autocomplete === 'username' || autocomplete === 'email') {
      score += 15;
    }

    // Bonus for autofocus
    if (input.hasAttribute('autofocus')) {
      score += 5;
    }

    return score;
  }

  function findLabelForInput(input) {
    // Check for label with 'for' attribute
    if (input.id) {
      const label = document.querySelector(`label[for="${input.id}"]`);
      if (label) return label.textContent || '';
    }

    // Check for parent label
    const parentLabel = input.closest('label');
    if (parentLabel) {
      return parentLabel.textContent || '';
    }

    // Check for aria-labelledby
    const labelledBy = input.getAttribute('aria-labelledby');
    if (labelledBy) {
      const labelEl = document.getElementById(labelledBy);
      if (labelEl) return labelEl.textContent || '';
    }

    return '';
  }

  function findSubmitButton(container) {
    const buttons = Array.from(container.querySelectorAll('button, input[type="submit"], input[type="button"], [role="button"]'));

    // First try to find by patterns
    for (const button of buttons) {
      const text = (button.textContent || button.value || button.getAttribute('aria-label') || '').toLowerCase();
      for (const pattern of SUBMIT_PATTERNS) {
        if (pattern.test(text)) {
          return button;
        }
      }
    }

    // Fall back to first submit button
    const submitBtn = container.querySelector('button[type="submit"], input[type="submit"]');
    if (submitBtn) return submitBtn;

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

    // Set new value using native setter
    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    nativeInputValueSetter.call(field, value);

    // Dispatch events to trigger validation
    field.dispatchEvent(new Event('input', { bubbles: true }));
    field.dispatchEvent(new Event('change', { bubbles: true }));
    field.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true }));
    field.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true }));

    // Highlight the field briefly
    highlightField(field);

    return true;
  }

  function highlightField(field) {
    const originalOutline = field.style.outline;
    const originalTransition = field.style.transition;

    field.style.transition = 'outline 0.15s ease-out';
    field.style.outline = '2px solid #16a34a';

    setTimeout(() => {
      field.style.outline = originalOutline;
      setTimeout(() => {
        field.style.transition = originalTransition;
      }, 150);
    }, 300);
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
  // Clipboard with auto-clear
  // ============================================================================

  async function copyWithTimeout(text, timeoutMs = 30000) {
    try {
      await navigator.clipboard.writeText(text);

      setTimeout(async () => {
        try {
          const current = await navigator.clipboard.readText();
          if (current === text) {
            await navigator.clipboard.writeText('');
          }
        } catch {
          // Clipboard access denied or text already changed
        }
      }, timeoutMs);

      return true;
    } catch {
      return false;
    }
  }

  // ============================================================================
  // Notification Bar (for auto-fill prompt)
  // ============================================================================

  let notificationBar = null;

  function showAutoFillPrompt(entry) {
    hideNotificationBar();

    notificationBar = document.createElement('div');
    notificationBar.id = 'pwdvault-autofill-bar';

    const style = document.createElement('style');
    style.textContent = `
      #pwdvault-autofill-bar {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        background: linear-gradient(135deg, #1e1e2e 0%, #2d2d44 100%);
        padding: 12px 20px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        font-size: 14px;
        color: #e0e0e0;
        z-index: 2147483646;
        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.3);
        animation: slideDown 0.3s ease-out;
      }
      @keyframes slideDown {
        from { transform: translateY(-100%); }
        to { transform: translateY(0); }
      }
      #pwdvault-autofill-bar .pv-bar-content {
        display: flex;
        align-items: center;
        gap: 12px;
      }
      #pwdvault-autofill-bar .pv-icon {
        width: 28px;
        height: 28px;
        background: #6366f1;
        border-radius: 6px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-weight: 600;
        color: #fff;
        font-size: 12px;
      }
      #pwdvault-autofill-bar .pv-text {
        display: flex;
        flex-direction: column;
      }
      #pwdvault-autofill-bar .pv-title {
        font-weight: 500;
      }
      #pwdvault-autofill-bar .pv-subtitle {
        font-size: 12px;
        color: #888;
      }
      #pwdvault-autofill-bar .pv-actions {
        display: flex;
        gap: 8px;
      }
      #pwdvault-autofill-bar .pv-btn {
        padding: 8px 16px;
        border-radius: 6px;
        border: none;
        font-size: 13px;
        font-weight: 500;
        cursor: pointer;
        transition: all 0.2s;
      }
      #pwdvault-autofill-bar .pv-btn-primary {
        background: #6366f1;
        color: white;
      }
      #pwdvault-autofill-bar .pv-btn-primary:hover {
        background: #4f46e5;
      }
      #pwdvault-autofill-bar .pv-btn-secondary {
        background: #333;
        color: #aaa;
      }
      #pwdvault-autofill-bar .pv-btn-secondary:hover {
        background: #444;
        color: #fff;
      }
    `;
    notificationBar.appendChild(style);

    const barContent = document.createElement('div');
    barContent.className = 'pv-bar-content';

    const icon = document.createElement('div');
    icon.className = 'pv-icon';
    icon.textContent = entry.title.charAt(0).toUpperCase();
    barContent.appendChild(icon);

    const text = document.createElement('div');
    text.className = 'pv-text';
    const titleSpan = document.createElement('span');
    titleSpan.className = 'pv-title';
    titleSpan.textContent = 'Fill credentials for ' + entry.title + '?';
    text.appendChild(titleSpan);
    const subtitleSpan = document.createElement('span');
    subtitleSpan.className = 'pv-subtitle';
    subtitleSpan.textContent = entry.username;
    text.appendChild(subtitleSpan);
    barContent.appendChild(text);

    notificationBar.appendChild(barContent);

    const actions = document.createElement('div');
    actions.className = 'pv-actions';

    const dismissBtn = document.createElement('button');
    dismissBtn.className = 'pv-btn pv-btn-secondary';
    dismissBtn.id = 'pv-dismiss';
    dismissBtn.textContent = 'Dismiss';
    actions.appendChild(dismissBtn);

    const fillBtn = document.createElement('button');
    fillBtn.className = 'pv-btn pv-btn-primary';
    fillBtn.id = 'pv-fill';
    fillBtn.textContent = 'Fill';
    actions.appendChild(fillBtn);

    notificationBar.appendChild(actions);

    notificationBar.querySelector('#pv-fill').addEventListener('click', async () => {
      hideNotificationBar();
      autofillLogin(entry.username, entry.password);
    });

    notificationBar.querySelector('#pv-dismiss').addEventListener('click', () => {
      hideNotificationBar();
    });

    document.body.appendChild(notificationBar);

    // Auto-dismiss after 10 seconds
    setTimeout(() => {
      hideNotificationBar();
    }, 10000);
  }

  function hideNotificationBar() {
    if (notificationBar && notificationBar.parentNode) {
      notificationBar.parentNode.removeChild(notificationBar);
      notificationBar = null;
    }
  }

  // ============================================================================
  // UI Overlay
  // ============================================================================

  let overlay = null;
  let cachedEntries = null;

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
          animation: fadeIn 0.2s ease-out;
        }
        @keyframes fadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
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
          flex-shrink: 0;
        }
        .pwdvault-info {
          flex: 1;
          min-width: 0;
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
        .pwdvault-item-actions {
          display: flex;
          gap: 4px;
          opacity: 0;
          transition: opacity 0.2s;
        }
        .pwdvault-item:hover .pwdvault-item-actions {
          opacity: 1;
        }
        .pwdvault-action-btn {
          width: 28px;
          height: 28px;
          border-radius: 6px;
          border: none;
          background: #333;
          color: #888;
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
          transition: all 0.2s;
        }
        .pwdvault-action-btn:hover {
          background: #444;
          color: #fff;
        }
        .pwdvault-action-btn svg {
          width: 14px;
          height: 14px;
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
          <button id="pwdvault-close">x</button>
        </div>
        <input id="pwdvault-search" type="text" placeholder="Search passwords...">
        <div id="pwdvault-content"></div>
      </div>
    `;

    overlay.querySelector('#pwdvault-close').addEventListener('click', hideOverlay);
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) hideOverlay();
    });

    // Keyboard shortcut to close
    overlay.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') hideOverlay();
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
        content.innerHTML = '';
        const statusEl = document.createElement('div');
        statusEl.id = 'pwdvault-status';
        statusEl.className = 'error';
        statusEl.textContent = escapeHtml(response.error);
        content.appendChild(statusEl);
        return;
      }

      cachedEntries = response;
      renderEntries(response);
    } catch (error) {
      content.innerHTML = '';
      const statusEl = document.createElement('div');
      statusEl.id = 'pwdvault-status';
      statusEl.className = 'error';
      statusEl.textContent = 'Failed to load entries: ' + escapeHtml(error.message || 'Unknown error');
      content.appendChild(statusEl);
    }
  }

  function renderEntries(entries) {
    const content = overlay.querySelector('#pwdvault-content');

    if (!entries || entries.length === 0) {
      content.innerHTML = '';
      const emptyEl = document.createElement('div');
      emptyEl.id = 'pwdvault-empty';
      emptyEl.textContent = 'No passwords found for this site';
      content.appendChild(emptyEl);
      return;
    }

    const list = document.createElement('div');
    list.id = 'pwdvault-list';

    entries.forEach(entry => {
      const item = document.createElement('div');
      item.className = 'pwdvault-item';

      const icon = document.createElement('div');
      icon.className = 'pwdvault-icon';
      // Use first character safely - textContent is safe
      icon.textContent = entry.title ? entry.title.charAt(0) : '?';

      const info = document.createElement('div');
      info.className = 'pwdvault-info';
      const h4 = document.createElement('h4');
      h4.textContent = entry.title || 'Untitled';
      const p = document.createElement('p');
      p.textContent = entry.username || 'No username';
      info.appendChild(h4);
      info.appendChild(p);

      const actionsDiv = document.createElement('div');
      actionsDiv.className = 'pwdvault-item-actions';

      const copyBtn = document.createElement('button');
      copyBtn.className = 'pwdvault-action-btn';
      copyBtn.setAttribute('data-action', 'copy');
      // Escape the ID attribute value to prevent XSS
      copyBtn.setAttribute('data-id', escapeHtml(entry.id));
      copyBtn.title = 'Copy password';
      copyBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>';
      actionsDiv.appendChild(copyBtn);

      item.appendChild(icon);
      item.appendChild(info);
      item.appendChild(actionsDiv);

      // Click to fill
      item.addEventListener('click', (e) => {
        if (!e.target.closest('.pwdvault-action-btn')) {
          selectEntry(entry.id);
        }
      });

      // Copy button
      copyBtn.addEventListener('click', async (e) => {
        e.stopPropagation();
        await copyEntryPassword(entry.id);
      });

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
      showNotification('Failed to get entry: ' + escapeHtml(error.message || 'Unknown error'), 'error');
    }
  }

  async function copyEntryPassword(id) {
    try {
      const entry = await chrome.runtime.sendMessage({
        type: 'GET_ENTRY',
        id
      });

      if (entry.error) {
        showNotification(entry.error, 'error');
        return;
      }

      const success = await copyWithTimeout(entry.password);
      if (success) {
        showNotification('Password copied (auto-clears in 30s)', 'success');
      } else {
        showNotification('Failed to copy password', 'error');
      }
    } catch (error) {
      showNotification('Failed to copy password: ' + escapeHtml(error.message || 'Unknown error'), 'error');
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
  let entryCount = 0;

  function createFloatingButton(entries = null) {
    if (floatingButton) {
      updateFloatingButtonBadge(entries);
      return;
    }

    const loginForm = findLoginForm();
    if (!loginForm || !loginForm.passwordField) return;

    entryCount = entries ? entries.length : 0;

    floatingButton = document.createElement('div');
    floatingButton.id = 'pwdvault-floating-btn';
    floatingButton.innerHTML = `
      <style>
        #pwdvault-floating-btn {
          position: fixed;
          width: 40px;
          height: 40px;
          background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          cursor: pointer;
          box-shadow: 0 2px 8px rgba(99, 102, 241, 0.4);
          z-index: 2147483646;
          transition: transform 0.2s, opacity 0.3s;
          animation: fadeInFloat 0.3s ease-out;
          opacity: 0;
        }
        @keyframes fadeInFloat {
          from { opacity: 0; transform: scale(0.8); }
          to { opacity: 1; transform: scale(1); }
        }
        #pwdvault-floating-btn:hover {
          transform: scale(1.1);
        }
        #pwdvault-floating-btn svg {
          width: 20px;
          height: 20px;
          fill: white;
        }
        #pwdvault-badge {
          position: absolute;
          top: -4px;
          right: -4px;
          min-width: 18px;
          height: 18px;
          background: #16a34a;
          border-radius: 9px;
          font-size: 11px;
          font-weight: 600;
          color: white;
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 0 4px;
          display: none;
        }
      </style>
      <svg viewBox="0 0 24 24">
        <path d="M12 2C9.24 2 7 4.24 7 7v2H6c-1.1 0-2 .9-2 2v9c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2v-9c0-1.1-.9-2-2-2h-1V7c0-2.76-2.24-5-5-5zm0 2c1.66 0 3 1.34 3 3v2H9V7c0-1.66 1.34-3 3-3zm0 10c1.1 0 2 .9 2 2s-.9 2-2 2-2-.9-2-2 .9-2 2-2z"/>
      </svg>
      <span id="pwdvault-badge"></span>
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

    // Trigger fade-in animation
    requestAnimationFrame(() => {
      floatingButton.style.opacity = '1';
    });

    updateFloatingButtonBadge(entries);
  }

  function updateFloatingButtonBadge(entries) {
    if (!floatingButton) return;

    const badge = floatingButton.querySelector('#pwdvault-badge');
    if (!badge) return;

    const count = entries ? entries.length : 0;
    entryCount = count;

    if (count > 1) {
      badge.textContent = count;
      badge.style.display = 'flex';
    } else {
      badge.style.display = 'none';
    }
  }

  // ============================================================================
  // Keyboard Shortcuts
  // ============================================================================

  document.addEventListener('keydown', (e) => {
    // Ctrl+Shift+L (Cmd+Shift+L on Mac) to trigger manual fill
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === 'l') {
      e.preventDefault();
      showOverlay();
    }
  });

  // ============================================================================
  // Auto-fill Prompt Logic
  // ============================================================================

  async function checkForAutoFillPrompt() {
    const loginForm = findLoginForm();
    if (!loginForm || !loginForm.passwordField) return;

    try {
      const entries = await chrome.runtime.sendMessage({
        type: 'GET_ENTRIES_FOR_URL',
        url: window.location.href
      });

      if (entries && !entries.error && entries.length === 1) {
        // Exactly one matching entry - show prompt
        const entry = await chrome.runtime.sendMessage({
          type: 'GET_ENTRY',
          id: entries[0].id
        });
        if (entry && !entry.error) {
          showAutoFillPrompt(entry);
        }
      }

      // Update floating button with entry count
      createFloatingButton(entries);
    } catch (error) {
      console.log('Auto-fill check failed:', error);
    }
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
        sendResponse({ hasForm: !!form, formType: form?.formType });
        break;

      default:
        sendResponse({ error: 'Unknown message type' });
    }
    return true;
  });

  // ============================================================================
  // Initialization
  // ============================================================================

  let initialized = false;

  function init() {
    if (initialized) return;
    initialized = true;

    // Wait for page to be ready
    const ready = () => {
      setTimeout(() => {
        createFloatingButton();
        checkForAutoFillPrompt();
      }, 500);
    };

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', ready);
    } else {
      ready();
    }
  }

  // Re-check for forms on dynamic page changes
  let debounceTimer = null;
  const observer = new MutationObserver(() => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      if (!floatingButton) {
        createFloatingButton();
        checkForAutoFillPrompt();
      }
    }, 250);
  });

  // Start observing when body is available
  if (document.body) {
    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
    init();
  } else {
    document.addEventListener('DOMContentLoaded', () => {
      observer.observe(document.body, {
        childList: true,
        subtree: true
      });
      init();
    });
  }

})();
