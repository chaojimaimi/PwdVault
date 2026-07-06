import { useState } from 'react';
import { useApp } from '../context/AppContext';
import { useTheme } from '../hooks/useTheme';
import { showToast } from '../utils/toast';
import { BackHeader } from '../components/BackHeader';
import type { Settings } from '../types';

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

  const handleBack = () => {
    actions.navigate('vault');
  };

  const handleSave = async () => {
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

  return (
    <div className="generator-screen">
      <BackHeader title="Settings" onBack={handleBack} />

      <div className="generator-content">
        <div className="settings-section">
          <h3 className="settings-section-title">Theme</h3>
          <div className="theme-selector">
            {themes.map((t) => (
              <button
                key={t}
                className={`theme-option ${theme === t ? 'active' : ''}`}
                onClick={() => setTheme(t)}
              >
                <div className={`theme-option-dot theme-option-dot-${t}`} />
                <span className="theme-option-name">{t.charAt(0).toUpperCase() + t.slice(1)}</span>
              </button>
            ))}
          </div>
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
              onChange={(e) => setSettings({ ...settings, check_updates: e.target.checked })}
            />
          </div>
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
        </div>
      </div>

      <div className="generator-actions">
        <button className="btn btn-primary" onClick={handleSave} disabled={saving}>
          {saving ? 'Saving...' : 'Save Settings'}
        </button>
        <button className="btn btn-secondary btn-full" onClick={() => actions.navigate('importExport')}>
          Backup & Restore
        </button>
      </div>
    </div>
  );
}
