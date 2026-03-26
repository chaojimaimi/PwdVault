import { useEffect } from 'react';
import { useApp } from '../context/AppContext';
import type { EntrySummary } from '../types';

function getInitials(title: string): string {
  return title.charAt(0).toUpperCase();
}

export function VaultScreen() {
  const { state, actions } = useApp();

  useEffect(() => {
    if (state.isUnlocked) {
      actions.loadEntries();
    }
  }, [state.isUnlocked]);

  const filteredEntries = state.entries.filter((entry) => {
    if (!state.searchQuery) return true;
    const query = state.searchQuery.toLowerCase();
    return (
      entry.title.toLowerCase().includes(query) ||
      entry.username.toLowerCase().includes(query) ||
      (entry.url && entry.url.toLowerCase().includes(query))
    );
  });

  const handleEntryClick = async (entry: EntrySummary) => {
    await actions.selectEntry(entry.id);
    actions.navigate('entry');
  };

  const handleAddClick = () => {
    actions.selectEntry(null);
    actions.navigate('entry');
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
          <button className="btn btn-icon" onClick={handleGeneratorClick} title="Password Generator">
            <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 2v4m0 12v4M4.93 4.93l2.83 2.83m8.48 8.48l2.83 2.83M2 12h4m12 0h4M4.93 19.07l2.83-2.83m8.48-8.48l2.83-2.83" />
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
        <input
          type="text"
          className="search-input"
          placeholder="Search passwords..."
          value={state.searchQuery}
          onChange={(e) => actions.setSearchQuery(e.target.value)}
        />
      </div>

      <div className="entry-list">
        {filteredEntries.length === 0 ? (
          <div className="empty-state">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
              <path d="M7 11V7a5 5 0 0110 0v4" />
            </svg>
            <p>{state.searchQuery ? 'No matching passwords found' : 'No passwords saved yet'}</p>
            <p style={{ fontSize: '0.8rem', marginTop: '0.5rem' }}>
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