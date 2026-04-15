import { useEffect, useState } from 'react';
import { useApp } from '../context/AppContext';
import DeleteConfirmModal from '../components/DeleteConfirmModal';

export default function GroupManager() {
  const { state, actions } = useApp();
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editingName, setEditingName] = useState('');
  const [newGroupName, setNewGroupName] = useState('');
  const [isCreating, setIsCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<{ id: string; name: string } | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);

  useEffect(() => {
    actions.loadGroups();
  }, []);

  const handleCreate = async () => {
    const name = newGroupName.trim();
    if (!name) return;
    setError(null);
    try {
      await actions.createGroup(name);
      setNewGroupName('');
      setIsCreating(false);
    } catch {
      setError('Failed to create group');
    }
  };

  const startEdit = (id: string, name: string) => {
    setEditingId(id);
    setEditingName(name);
  };

  const saveEdit = async () => {
    if (!editingId || !editingName.trim()) return;
    setError(null);
    try {
      await actions.updateGroup(editingId, editingName.trim());
      setEditingId(null);
      setEditingName('');
    } catch {
      setError('Failed to rename group');
    }
  };

  const cancelEdit = () => {
    setEditingId(null);
    setEditingName('');
  };

  const onConfirmDelete = async () => {
    if (!deleteTarget) return;
    setIsDeleting(true);
    setError(null);
    try {
      await actions.deleteGroup(deleteTarget.id);
      setDeleteTarget(null);
    } catch {
      setError('Failed to delete group');
    } finally {
      setIsDeleting(false);
    }
  };

  const handleBack = () => {
    actions.navigate('vault');
  };

  const groupCount = (groupId: string) =>
    state.entries.filter((e) => (e as any).group_id === groupId).length;

  return (
    <div className="group-manager">
      <header className="entry-header">
        <button className="btn btn-icon" onClick={handleBack}>
          <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M19 12H5M12 19l-7-7 7-7" />
          </svg>
        </button>
        <h2>Groups</h2>
        <button
          className="btn btn-icon"
          onClick={() => { setIsCreating(true); setNewGroupName(''); }}
          title="New group"
        >
          <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 5v14M5 12h14" />
          </svg>
        </button>
      </header>

      <div className="group-manager-content">
        {error && <div className="error-message">{error}</div>}

        {isCreating && (
          <div className="group-create-bar">
            <svg className="group-create-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z" />
            </svg>
            <input
              type="text"
              className="form-input group-create-input"
              value={newGroupName}
              onChange={(e) => setNewGroupName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') handleCreate();
                if (e.key === 'Escape') { setIsCreating(false); setNewGroupName(''); }
              }}
              placeholder="New group name..."
              autoFocus
            />
            <button className="btn btn-primary group-create-save" onClick={handleCreate} disabled={!newGroupName.trim()}>
              Create
            </button>
            <button className="btn btn-icon group-create-cancel" onClick={() => { setIsCreating(false); setNewGroupName(''); }}>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="16" height="16">
                <path d="M18 6L6 18M6 6l12 12" />
              </svg>
            </button>
          </div>
        )}

        {state.groups.length === 0 && !isCreating && (
          <div className="empty-state">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z" />
            </svg>
            <p>No groups yet</p>
            <p style={{ fontSize: 'var(--text-micro)', marginTop: 'var(--space-xs)' }}>
              Tap + to create your first group
            </p>
          </div>
        )}

        <div className="group-list">
          {state.groups.map((g) => (
            <div key={g.id} className="group-card">
              {editingId === g.id ? (
                <div className="group-card-edit">
                  <input
                    value={editingName}
                    onChange={(e) => setEditingName(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') saveEdit();
                      if (e.key === 'Escape') cancelEdit();
                    }}
                    className="form-input group-edit-input"
                    autoFocus
                  />
                  <button className="btn btn-primary group-edit-save" onClick={saveEdit}>Save</button>
                  <button className="btn btn-secondary group-edit-cancel" onClick={cancelEdit}>Cancel</button>
                </div>
              ) : (
                <>
                  <div className="group-card-info">
                    <div className="group-card-icon">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z" />
                      </svg>
                    </div>
                    <div className="group-card-text">
                      <span className="group-card-name">{g.name}</span>
                      <span className="group-card-count">{groupCount(g.id)} {groupCount(g.id) === 1 ? 'entry' : 'entries'}</span>
                    </div>
                  </div>
                  <div className="group-card-actions">
                    <button className="btn btn-icon group-action-rename" onClick={() => startEdit(g.id, g.name)} title="Rename">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M12 20h9M16.5 3.5a2.121 2.121 0 013 3L7 19l-4 1 1-4L16.5 3.5z" />
                      </svg>
                    </button>
                    <button className="btn btn-icon group-action-delete" onClick={() => setDeleteTarget({ id: g.id, name: g.name })} title="Delete">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <polyline points="3,6 5,6 21,6" />
                        <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2" />
                      </svg>
                    </button>
                  </div>
                </>
              )}
            </div>
          ))}
        </div>
      </div>

      <DeleteConfirmModal
        isOpen={!!deleteTarget}
        message={`Delete group "${deleteTarget?.name || ''}"? Entries in this group will become ungrouped.`}
        onConfirm={onConfirmDelete}
        onCancel={() => setDeleteTarget(null)}
        isDeleting={isDeleting}
      />
    </div>
  );
}
