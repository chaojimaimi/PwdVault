// PwdVault Content Script — Shadow DOM mounting (file 3/6).
// One shared stylesheet plus the single mountShadowHost choke point every
// injected UI root goes through (v1.3.2 style isolation; guarded by
// content-shadow.test.js). Same namespace rules as content-forms.js.

(function () {
	"use strict";

	globalThis.PwdVaultContent ??= {};

	// ============================================================================
	// Shadow DOM mounting (style isolation)
	// ============================================================================

	// One shared stylesheet injected into every shadow root. A shadow tree
	// cannot read the host page's CSS custom properties, so the design tokens
	// are pinned in the :host block below — they mirror the desktop Light
	// theme (src/styles/themes.css); resync both when the palette changes.
	// The five @keyframes live here too: shadow-scoped, so the page can neither
	// clobber nor reuse them.
	const SHADOW_CSS = `
    :host {
      /* Design tokens — mirror of the desktop Light theme (themes.css). */
      --pv-primary: #1E3A5F;
      --pv-primary-hover: #153050;
      --pv-accent: #0D9488;
      --pv-success: #059669;
      --pv-danger: #DC2626;
      --pv-bg: #F8FAFC;
      --pv-surface: #FFFFFF;
      --pv-input: #EDEEF2;
      --pv-text: #0F172A;
      --pv-text-secondary: #475569;
      --pv-text-muted: #5B6B80;
      --pv-border: rgba(0, 0, 0, 0.06);
      --pv-border-strong: rgba(0, 0, 0, 0.10);
      /* Cut inheritance from the host element so a page rule targeting our
         wrapper div cannot restyle the widgets through inheritable
         properties. Custom properties survive the all shorthand, and the
         two declarations below re-pin what the widgets rely on. */
      all: initial;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      color: var(--pv-text);
    }

    /* --- Auto-fill prompt bar (position/z-index live on the host) --- */
    #pwdvault-autofill-bar {
      width: 100%;
      background: var(--pv-surface);
      padding: 12px 20px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-size: 14px;
      color: var(--pv-text);
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.15);
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
      background: var(--pv-primary);
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
      color: var(--pv-text-muted);
    }
    #pwdvault-autofill-bar .pv-error {
      font-size: 12px;
      color: var(--pv-danger);
    }
    #pwdvault-autofill-bar .pv-actions {
      display: flex;
      gap: 8px;
    }
    #pwdvault-autofill-bar .pv-btn,
    #pwdvault-save-bar .pv-btn {
      padding: 8px 16px;
      border-radius: 6px;
      border: none;
      font-size: 13px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s;
      font-family: inherit;
    }
    #pwdvault-autofill-bar .pv-btn-primary,
    #pwdvault-save-bar .pv-btn-primary {
      background: var(--pv-primary);
      color: #fff;
    }
    #pwdvault-autofill-bar .pv-btn-primary:hover,
    #pwdvault-save-bar .pv-btn-primary:hover {
      background: var(--pv-primary-hover);
    }
    #pwdvault-autofill-bar .pv-btn-secondary,
    #pwdvault-save-bar .pv-btn-secondary {
      background: var(--pv-input);
      color: var(--pv-text-secondary);
    }
    #pwdvault-autofill-bar .pv-btn-secondary:hover,
    #pwdvault-save-bar .pv-btn-secondary:hover {
      background: var(--pv-border-strong);
      color: var(--pv-text);
    }

    /* --- Save/update prompt bar (bottom; position lives on the host) --- */
    #pwdvault-save-bar {
      width: 100%;
      box-sizing: border-box;
      background: var(--pv-surface);
      padding: 12px 20px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      font-size: 14px;
      color: var(--pv-text);
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.15);
      animation: slideUp 0.3s ease-out;
    }
    @keyframes slideUp {
      from { transform: translateY(100%); }
      to { transform: translateY(0); }
    }
    #pwdvault-save-bar .pv-save-text {
      font-weight: 500;
      min-width: 0;
    }
    #pwdvault-save-bar .pv-actions {
      display: flex;
      gap: 8px;
      flex-shrink: 0;
    }

    /* --- Overlay (backdrop fills the fixed host) --- */
    #pwdvault-overlay {
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.5);
      display: flex;
      align-items: flex-start;
      justify-content: center;
      padding-top: 100px;
      font-size: 14px;
      color: var(--pv-text);
      animation: fadeIn 0.2s ease-out;
    }
    @keyframes fadeIn {
      from { opacity: 0; }
      to { opacity: 1; }
    }
    #pwdvault-modal {
      background: var(--pv-surface);
      border-radius: 12px;
      padding: 20px;
      min-width: 320px;
      max-width: 400px;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
      color: var(--pv-text);
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
      color: var(--pv-text-muted);
      font-size: 20px;
      cursor: pointer;
      padding: 4px;
      font-family: inherit;
    }
    #pwdvault-close:hover {
      color: var(--pv-text);
    }
    #pwdvault-search {
      width: 100%;
      padding: 10px 12px;
      border: 1px solid var(--pv-border-strong);
      border-radius: 8px;
      background: var(--pv-input);
      color: var(--pv-text);
      font-size: 14px;
      margin-bottom: 12px;
      box-sizing: border-box;
      font-family: inherit;
    }
    #pwdvault-search:focus {
      outline: none;
      border-color: var(--pv-primary);
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
      background: var(--pv-input);
    }
    .pwdvault-icon {
      width: 36px;
      height: 36px;
      border-radius: 8px;
      background: var(--pv-primary);
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
      color: var(--pv-text-muted);
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
      background: var(--pv-input);
      color: var(--pv-text-muted);
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: all 0.2s;
    }
    .pwdvault-action-btn:hover {
      background: var(--pv-border-strong);
      color: var(--pv-text);
    }
    .pwdvault-action-btn svg {
      width: 14px;
      height: 14px;
    }
    #pwdvault-empty {
      text-align: center;
      padding: 32px 16px;
      color: var(--pv-text-muted);
    }
    #pwdvault-status {
      text-align: center;
      padding: 32px 16px;
    }
    #pwdvault-status.error {
      color: var(--pv-danger);
    }

    /* --- Toast (bottom-right; position lives on the host) --- */
    #pwdvault-notification {
      padding: 12px 20px;
      border-radius: 8px;
      font-size: 14px;
      animation: slideIn 0.3s ease-out;
      color: #fff;
    }
    #pwdvault-notification.error { background: var(--pv-danger); }
    #pwdvault-notification.success { background: var(--pv-success); }
    #pwdvault-notification.info { background: var(--pv-primary); }
    @keyframes slideIn {
      from { transform: translateY(20px); opacity: 0; }
      to { transform: translateY(0); opacity: 1; }
    }

    /* --- Floating button (position/top live on the host) --- */
    #pwdvault-floating-btn {
      position: relative;
      width: 40px;
      height: 40px;
      background: linear-gradient(135deg, var(--pv-primary) 0%, var(--pv-accent) 100%);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      box-shadow: 0 2px 8px rgba(30, 58, 95, 0.4);
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
      background: var(--pv-success);
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
  `;

	// Creates a position:fixed host element carrying one closed shadow root
	// pre-seeded with the shared stylesheet. `hostCss` holds the positioning
	// that used to live on the injected roots (inline styles beat page CSS,
	// so the page cannot move or unstack the widgets). closed mode keeps the
	// page from reaching the root via el.shadowRoot — this script only ever
	// uses the reference returned here.
	function mountShadowHost(hostCss) {
		const host = document.createElement("div");
		host.style.cssText = hostCss;
		const shadowRoot = host.attachShadow({ mode: "closed" });
		const style = document.createElement("style");
		style.textContent = SHADOW_CSS;
		shadowRoot.appendChild(style);
		return { host, shadowRoot };
	}

	// ============================================================================
	// Namespace exports (file 3/6) — the single shadow-root mount choke point.
	// ============================================================================
	globalThis.PwdVaultContent.mountShadowHost = mountShadowHost;
})();
