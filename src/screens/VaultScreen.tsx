import { useEffect, useMemo, useState } from 'react';
import { useApp } from '../context/AppContext';
import { useTheme } from '../hooks/useTheme';
import { copyWithTimeout } from '../utils/clipboard';
import { searchEntries } from '../utils/search';
import { showToast } from '../utils/toast';
import { UpdateNotification } from '../components/UpdateNotification';
import { PlusIcon, GenerateIcon, SettingsIcon, LockIcon, SearchIcon, FolderIcon, UserIcon, CopyIcon } from '../components/Icons';
import type { EntrySummary } from '../types';

function getInitials(title: string): string {
  return title.charAt(0).toUpperCase();
}

export function VaultScreen() {
  const { state, dispatch, actions } = useApp();
  const { toggleTheme } = useTheme();
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

  return (
    <div className="vault-container">
      {state.updateInfo && (
        <UpdateNotification
          updateInfo={state.updateInfo}
          onDismiss={() => dispatch({ type: 'SET_UPDATE_INFO', payload: null })}
        />
      )}
      <header className="vault-header">
        <h1>PwdVault</h1>
        <div className="header-actions">
          <button className="btn btn-icon" onClick={handleAddClick} title="Add password" aria-label="Add password">
            <PlusIcon />
          </button>
          <button className="theme-dot" onClick={toggleTheme} title="Switch theme" aria-label="Toggle theme" />
          <div className="header-separator" />
          <button className="btn btn-icon" onClick={() => actions.navigate('generator')} title="Password Generator" aria-label="Password generator">
            <GenerateIcon />
          </button>
          <button className="btn btn-icon" onClick={() => actions.navigate('settings')} title="Settings" aria-label="Settings">
            <SettingsIcon />
          </button>
          <button className="btn btn-icon" onClick={() => actions.lock()} title="Lock Vault" aria-label="Lock vault">
            <LockIcon />
          </button>
        </div>
      </header>

      <div className="search-bar">
        <div className="search-input-wrapper">
          <SearchIcon className="search-icon" />
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
          <button className="group-manage-btn" onClick={handleManageGroups} title="Manage groups" aria-label="Manage groups">
            <SettingsIcon size={14} />
          </button>
        </div>
      )}

      {state.groups.length === 0 && (
        <div className="group-tabs group-tabs-empty">
          <button className="group-manage-btn group-manage-first" onClick={handleManageGroups}>
            <FolderIcon size={14} />
            Create group
          </button>
        </div>
      )}

      <div className="entry-list" role="list">
        {filteredEntries.length === 0 ? (
          <div className="empty-state" role="listitem">
            <LockIcon size={64} />
            <p>{state.searchQuery ? 'No matching passwords found' : 'No passwords saved yet'}</p>
            <p className="text-muted-hint">Tap + to add your first password</p>
          </div>
        ) : (
          filteredEntries.map((entry) => (
            <div
              key={entry.id}
              className="entry-item"
              role="listitem"
              tabIndex={0}
              aria-label={`${entry.title}, ${entry.username}`}
              onClick={() => handleEntryClick(entry)}
              onKeyDown={(e) => e.key === 'Enter' && handleEntryClick(entry)}
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
                  aria-label={`Copy username for ${entry.title}`}
                >
                  <UserIcon />
                </button>
                <button
                  className={`btn btn-icon btn-copy ${copiedId === entry.id ? 'copied' : ''}`}
                  onClick={(e) => handleCopyPassword(e, entry)}
                  title={copiedId === entry.id ? 'Copied!' : 'Copy password'}
                  aria-label={`Copy password for ${entry.title}`}
                >
                  <CopyIcon />
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
