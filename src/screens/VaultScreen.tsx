import { useEffect, useMemo, useState } from 'react';
import { useApp } from '../context/AppContext';
import { useTheme } from '../hooks/useTheme';
import { copyWithTimeout } from '../utils/clipboard';
import { searchEntries } from '../utils/search';
import { showToast } from '../utils/toast';
import type { EntrySummary } from '../types';

function getInitials(title: string): string {
  return title.charAt(0).toUpperCase();
}

export function VaultScreen() {
  const { state, actions } = useApp();
  const { theme, setTheme } = useTheme();
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    if (state.isUnlocked) {
      actions.loadEntries();
      actions.loadGroups();
    }
  }, [state.isUnlocked]);

  const filteredEntries = useMemo(() => {
    let entries = state.entries;
    if (state.selectedGroupId) {
      entries = entries.filter((entry) => entry.group_id === state.selectedGroupId);
    }
    return searchEntries(entries, state.searchQuery);
  }, [state.entries, state.selectedGroupId, state.searchQuery]);

  const handleEntryClick = async (entry: EntrySummary) => {
    await actions.selectEntry(entry.id);
    actions.navigate('entry');
  };

  const handleCopyUsername = async (e: React.MouseEvent, username: string) => {
    e.stopPropagation();
    await copyWithTimeout(username);
    showToast('Username copied');
  };

  const handleCopyPassword = async (e: React.MouseEvent, entry: EntrySummary) => {
    e.stopPropagation();
    const fullEntry = await actions.getEntry(entry.id);
    if (fullEntry?.password) {
      await copyWithTimeout(fullEntry.password);
      setCopiedId(entry.id);
      showToast('Password copied (auto-clears in 30s)');
      setTimeout(() => setCopiedId(null), 2000);
    }
  };

  const handleAddClick = () => {
    actions.selectEntry(null);
    actions.navigate('entry');
  };

  const handleManageGroups = () => {
    actions.navigate('groupManager');
  };

  const handleGeneratorClick = () => {
    actions.navigate('generator');
  };

  const handleLockClick = () => {
    actions.lock();
  };

  return (
    <div className="vault-container">
      <header className="vault-header">
        <h1>PwdVault</h1>
        <div className="header-actions">
          <div className="theme-switcher">
            <button
              className={`theme-dot theme-dot-classic ${theme === 'classic' ? 'active' : ''}`}
              onClick={() => setTheme('classic')}
              title="Classic"
            />
            <button
              className={`theme-dot theme-dot-cyber ${theme === 'cyber' ? 'active' : ''}`}
              onClick={() => setTheme('cyber')}
              title="Cyber"
            />
            <button
              className={`theme-dot theme-dot-hybrid ${theme === 'hybrid' ? 'active' : ''}`}
              onClick={() => setTheme('hybrid')}
              title="Hybrid"
            />
          </div>
          <button className="btn btn-icon" onClick={handleGeneratorClick} title="Password Generator">
            <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 2v4m0 12v4M4.93 4.93l2.83 2.83m8.48 8.48l2.83 2.83M2 12h4m12 0h4M4.93 19.07l2.83-2.83m8.48-8.48l2.83-2.83" />
            </svg>
          </button>
          <button className="btn btn-icon" onClick={() => actions.navigate('settings')} title="Settings">
            <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="3" />
              <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-2 2 2 2 0 01-2-2v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83 0 2 2 0 010-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 01-2-2 2 2 0 012-2h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 010-2.83 2 2 0 012.83 0l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 012-2 2 2 0 012 2v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 0 2 2 0 010 2.83l-.06.06A1.65 1.65 0 0019.32 9a1.65 1.65 0 001.51 1H21a2 2 0 012 2 2 2 0 01-2 2h-.09a1.65 1.65 0 00-1.51 1z" />
            </svg>
          </button>
          <button className="btn btn-icon" onClick={handleLockClick} title="Lock Vault">
            <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
              <path d="M7 11V7a5 5 0 0110 0v4" />
            </svg>
          </button>
        </div>
      </header>

      <div className="search-bar">
        <div className="search-input-wrapper">
          <svg className="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="11" cy="11" r="8" />
            <path d="M21 21l-4.35-4.35" />
          </svg>
          <input
            type="text"
            className="search-input"
            placeholder="Search passwords..."
            value={state.searchQuery}
            onChange={(e) => actions.setSearchQuery(e.target.value)}
          />
        </div>
      </div>

      {state.groups.length > 0 && (
        <div className="group-tabs">
          <div className="group-tabs-scroll">
            <button
              className={`group-tab ${!state.selectedGroupId ? 'active' : ''}`}
              onClick={() => actions.selectGroup(null)}
            >
              All
            </button>
            {state.groups.map((g) => (
              <button
                key={g.id}
                className={`group-tab ${state.selectedGroupId === g.id ? 'active' : ''}`}
                onClick={() => actions.selectGroup(g.id)}
              >
                {g.name}
              </button>
            ))}
          </div>
          <button className="group-manage-btn" onClick={handleManageGroups} title="Manage groups">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="3" />
              <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-2 2 2 2 0 01-2-2v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83 0 2 2 0 010-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 01-2-2 2 2 0 012-2h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 010-2.83 2 2 0 012.83 0l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 012-2 2 2 0 012 2v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 0 2 2 0 010 2.83l-.06.06A1.65 1.65 0 0019.32 9a1.65 1.65 0 001.51 1H21a2 2 0 012 2 2 2 0 01-2 2h-.09a1.65 1.65 0 00-1.51 1z" />
            </svg>
          </button>
        </div>
      )}

      {state.groups.length === 0 && (
        <div className="group-tabs group-tabs-empty">
          <button className="group-manage-btn group-manage-first" onClick={handleManageGroups}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="14" height="14">
              <path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z" />
            </svg>
            Create group
          </button>
        </div>
      )}

      <div className="entry-list">
        {filteredEntries.length === 0 ? (
          <div className="empty-state">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
              <path d="M7 11V7a5 5 0 0110 0v4" />
            </svg>
            <p>{state.searchQuery ? 'No matching passwords found' : 'No passwords saved yet'}</p>
            <p style={{ fontSize: 'var(--text-micro)', marginTop: 'var(--space-xs)' }}>
              Tap + to add your first password
            </p>
          </div>
        ) : (
          filteredEntries.map((entry) => (
            <div
              key={entry.id}
              className="entry-item"
              onClick={() => handleEntryClick(entry)}
            >
              <div className="entry-icon">{getInitials(entry.title)}</div>
              <div className="entry-info">
                <h3>{entry.title}</h3>
                <p>{entry.username}</p>
              </div>
              <div className="entry-actions-inline">
                <button
                  className="btn btn-icon btn-copy"
                  onClick={(e) => handleCopyUsername(e, entry.username)}
                  title="Copy username"
                >
                  <svg className="icon icon-small" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                    <circle cx="12" cy="7" r="4" />
                  </svg>
                </button>
                <button
                  className={`btn btn-icon btn-copy ${copiedId === entry.id ? 'copied' : ''}`}
                  onClick={(e) => handleCopyPassword(e, entry)}
                  title={copiedId === entry.id ? 'Copied!' : 'Copy password'}
                >
                  <svg className="icon icon-small" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                  </svg>
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      <button className="fab" onClick={handleAddClick}>
        +
      </button>
    </div>
  );
}
