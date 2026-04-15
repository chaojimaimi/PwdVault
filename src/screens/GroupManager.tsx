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

  return (
    <div className="group-manager">
      <header className="entry-header">
        <button className="btn btn-icon" onClick={handleBack}>
          <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M19 12H5M12 19l-7-7 7-7" />
          </svg>
        </button>
        <h2>Groups</h2>
        <div style={{ width: '40px' }} />
      </header>

      <div className="entry-content">
        {error && <div className="error-message">{error}</div>}

        <div style={{ marginBottom: '1rem' }}>
          {isCreating ? (
            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
              <input
                type="text"
                className="form-input"
                value={newGroupName}
                onChange={(e) => setNewGroupName(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleCreate()}
                placeholder="Group name"
                autoFocus
              />
              <button className="btn btn-primary" onClick={handleCreate}>Save</button>
              <button className="btn btn-secondary" onClick={() => { setIsCreating(false); setNewGroupName(''); }}>Cancel</button>
            </div>
          ) : (
            <button className="btn btn-primary" onClick={() => setIsCreating(true)}>New Group</button>
          )}
        </div>

        <div className="group-list">
          {state.groups.length === 0 && !isCreating && (
            <div className="empty-state">
              <p>No groups yet</p>
            </div>
          )}
          {state.groups.map((g) => (
            <div key={g.id} className="group-item">
              {editingId === g.id ? (
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', width: '100%' }}>
                  <input
                    value={editingName}
                    onChange={(e) => setEditingName(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && saveEdit()}
                    className="form-input"
                    autoFocus
                  />
                  <button className="btn" onClick={saveEdit}>Save</button>
                  <button className="btn btn-secondary" onClick={() => setEditingId(null)}>Cancel</button>
                </div>
              ) : (
                <>
                  <span>{g.name}</span>
                  <div>
                    <button className="btn" onClick={() => startEdit(g.id, g.name)}>Rename</button>
                    <button className="btn btn-danger" onClick={() => setDeleteTarget({ id: g.id, name: g.name })}>Delete</button>
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
