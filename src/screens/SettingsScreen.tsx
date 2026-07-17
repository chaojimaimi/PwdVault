import { useEffect, useMemo, useState } from 'react';
import { useApp } from '../context/AppContext';
import { useTheme } from '../hooks/useTheme';
import { showToast } from '../utils/toast';
import { BackHeader } from '../components/BackHeader';
import type { Settings } from '../types';
import { UnsavedChangesModal } from '../components/UnsavedChangesModal';
import { UPDATE_CHECK_AVAILABLE } from '../api/vault';
import { revokeExtensionAccess } from '../api/vault';
import { AccessibleDialog } from '../components/AccessibleDialog';

const AUTO_LOCK_OPTIONS = [
  { label: '1 minute', value: 60 },
  { label: '2 minutes', value: 120 },
  { label: '5 minutes', value: 300 },
  { label: '10 minutes', value: 600 },
  { label: '15 minutes', value: 900 },
  { label: '30 minutes', value: 1800 },
  { label: '1 hour', value: 3600 },
];

export function SettingsScreen() {
  const { state, actions } = useApp();
  const { theme, setTheme, themes } = useTheme();
  const [settings, setSettings] = useState<Settings>(state.settings);
  const [saving, setSaving] = useState(false);
  const [showUnsaved, setShowUnsaved] = useState(false);
  const [showRevoke, setShowRevoke] = useState(false);
  const [revoking, setRevoking] = useState(false);
  const charsetValid = settings.default_include_uppercase || settings.default_include_lowercase || settings.default_include_numbers || settings.default_include_symbols;
  const isDirty = useMemo(() => state.settingsStatus === 'success' && JSON.stringify(settings) !== JSON.stringify(state.settings), [settings, state.settings, state.settingsStatus]);

  useEffect(() => {
    if (state.settingsStatus === 'success') setSettings(state.settings);
  }, [state.settings, state.settingsStatus]);

  useEffect(() => {
    const warn = (event: BeforeUnloadEvent) => {
      if (!isDirty) return;
      event.preventDefault();
    };
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, [isDirty]);

  const handleBack = () => {
    if (isDirty) setShowUnsaved(true);
    else actions.navigate('vault');
  };

  const handleSave = async () => {
    if (saving || state.settingsStatus !== 'success' || !charsetValid) return;
    setSaving(true);
    try {
      await actions.updateSettings(settings);
      showToast('Settings saved');
      actions.navigate('vault');
    } catch {
      showToast('Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  const handleRevoke = async () => {
    if (revoking) return;
    setRevoking(true);
    try {
      await revokeExtensionAccess();
      setShowRevoke(false);
      showToast('Browser extension access revoked');
    } catch {
      showToast('Failed to revoke extension access');
    } finally {
      setRevoking(false);
    }
  };

  return (
    <div className="generator-screen screen-shell">
      <BackHeader title="Settings" onBack={handleBack} />

      <div className="generator-content screen-scroll-region">
        {(state.settingsStatus === 'idle' || state.settingsStatus === 'loading') && (
          <div className="loading" role="status"><span className="spinner" /><span>Loading settings…</span></div>
        )}
        {state.settingsStatus === 'error' && (
          <div className="resource-error" role="alert">
            <p>Could not load settings. Saving is disabled to protect your stored configuration.</p>
            <p className="text-muted-hint">{state.settingsError}</p>
            <button className="btn btn-secondary" onClick={() => void actions.loadSettings()}>Retry</button>
          </div>
        )}
        <fieldset disabled={state.settingsStatus !== 'success' || saving} className="settings-fieldset">
        <div className="settings-section">
          <h3 className="settings-section-title">Theme</h3>
          <div className="theme-selector">
            {themes.map((t) => (
              <button
                key={t}
                type="button"
                className={`theme-option ${theme === t ? 'active' : ''}`}
                onClick={() => setTheme(t)}
                aria-pressed={theme === t}
                aria-label={`Use ${t} theme`}
              >
                <div className={`theme-option-dot theme-option-dot-${t}`} />
                <span className="theme-option-name">{t.charAt(0).toUpperCase() + t.slice(1)}</span>
              </button>
            ))}
          </div>
        </div>

        <div className="settings-divider" />

        <div className="settings-section">
          <h3 className="settings-section-title">Browser Extension</h3>
          <p className="settings-hint settings-action-description">
            Invalidate all paired browser tokens. Extensions must pair again before they can access this vault.
          </p>
          <button type="button" className="btn btn-danger" onClick={() => setShowRevoke(true)}>
            Revoke Extension Access
          </button>
        </div>

        <div className="settings-divider" />

        <div className="settings-section">
          <h3 className="settings-section-title">Auto-Lock</h3>
          <div className="option-row">
            <label htmlFor="auto-lock">Lock after inactivity</label>
            <select
              id="auto-lock"
              className="settings-select"
              value={settings.auto_lock_secs}
              onChange={(e) => setSettings({ ...settings, auto_lock_secs: parseInt(e.target.value) })}
            >
              {AUTO_LOCK_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
          </div>
          <p className="settings-hint">Vault locks automatically when idle</p>
        </div>

        <div className="settings-divider" />

        <div className="settings-section">
          <h3 className="settings-section-title">Updates</h3>
          <div className="option-row">
            <label htmlFor="check-updates">Check for updates on startup</label>
            <input
              id="check-updates"
              type="checkbox"
              className="checkbox"
              checked={settings.check_updates}
              disabled={!UPDATE_CHECK_AVAILABLE}
              onChange={(e) => setSettings({ ...settings, check_updates: e.target.checked })}
            />
          </div>
          {!UPDATE_CHECK_AVAILABLE && (
            <p className="settings-hint">Disabled in private builds until a public trusted update feed is configured.</p>
          )}
        </div>

        <div className="settings-divider" />

        <div className="settings-section">
          <h3 className="settings-section-title">Default Generator Options</h3>
          <div className="option-row">
            <label htmlFor="def-length">Length: {settings.default_length}</label>
          </div>
          <div className="length-control">
            <input
              id="def-length"
              type="range"
              min="8"
              max="64"
              value={settings.default_length}
              aria-label="Default password length"
              aria-valuemin={8}
              aria-valuemax={64}
              aria-valuenow={settings.default_length}
              onChange={(e) => setSettings({ ...settings, default_length: parseInt(e.target.value) })}
            />
          </div>

          <div className="option-row">
            <label htmlFor="def-upper">Uppercase (A-Z)</label>
            <input
              id="def-upper"
              type="checkbox"
              className="checkbox"
              checked={settings.default_include_uppercase}
              onChange={(e) => setSettings({ ...settings, default_include_uppercase: e.target.checked })}
            />
          </div>

          <div className="option-row">
            <label htmlFor="def-lower">Lowercase (a-z)</label>
            <input
              id="def-lower"
              type="checkbox"
              className="checkbox"
              checked={settings.default_include_lowercase}
              onChange={(e) => setSettings({ ...settings, default_include_lowercase: e.target.checked })}
            />
          </div>

          <div className="option-row">
            <label htmlFor="def-numbers">Numbers (0-9)</label>
            <input
              id="def-numbers"
              type="checkbox"
              className="checkbox"
              checked={settings.default_include_numbers}
              onChange={(e) => setSettings({ ...settings, default_include_numbers: e.target.checked })}
            />
          </div>

          <div className="option-row">
            <label htmlFor="def-symbols">Symbols (!@#$...)</label>
            <input
              id="def-symbols"
              type="checkbox"
              className="checkbox"
              checked={settings.default_include_symbols}
              onChange={(e) => setSettings({ ...settings, default_include_symbols: e.target.checked })}
            />
          </div>
          {!charsetValid && <p className="error-message" role="alert">Select at least one character set.</p>}
        </div>
        </fieldset>
      </div>

      <div className="generator-actions">
        <button className="btn btn-primary" onClick={handleSave} disabled={saving || state.settingsStatus !== 'success' || !charsetValid}>
          {saving ? 'Saving...' : 'Save Settings'}
        </button>
        <button className="btn btn-secondary btn-full" onClick={() => actions.navigate('importExport')}>
          Backup & Restore
        </button>
      </div>
      <UnsavedChangesModal
        isOpen={showUnsaved}
        onStay={() => setShowUnsaved(false)}
        onDiscard={() => { setShowUnsaved(false); actions.navigate('vault'); }}
      />
      <AccessibleDialog
        isOpen={showRevoke}
        onClose={() => { if (!revoking) setShowRevoke(false); }}
        labelledBy="revoke-extension-title"
        describedBy="revoke-extension-description"
        className="confirm-modal"
        initialFocusSelector="[data-revoke-cancel]"
        closeOnOverlay={!revoking}
      >
        <div className="confirm-modal-header">
          <div className="confirm-modal-icon confirm-modal-icon-danger" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="M9 9l6 6M15 9l-6 6" />
            </svg>
          </div>
          <div>
            <h3 className="confirm-modal-title" id="revoke-extension-title">Revoke extension access?</h3>
            <p className="confirm-modal-subtitle">Vault data will not be changed</p>
          </div>
        </div>
        <div className="confirm-modal-body">
          <p id="revoke-extension-description">
            All currently paired browser extensions will be disconnected and must complete pairing again.
          </p>
        </div>
        <div className="confirm-modal-footer">
          <div className="confirm-modal-actions">
            <button className="btn btn-secondary" data-revoke-cancel onClick={() => setShowRevoke(false)} disabled={revoking}>Cancel</button>
            <button className="btn btn-danger" onClick={() => void handleRevoke()} disabled={revoking}>
              {revoking ? 'Revoking…' : 'Revoke Access'}
            </button>
          </div>
        </div>
      </AccessibleDialog>
    </div>
  );
}
