import { useEffect, useState } from 'react';
import { useApp } from '../context/AppContext';
import { BackHeader } from '../components/BackHeader';
import { PlusIcon, CloseIcon, FolderIcon, EditIcon, TrashIcon } from '../components/Icons';
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
    state.entries.filter((e) => e.group_id === groupId).length;

  return (
    <div className="group-manager screen-shell">
      <BackHeader
        title="Groups"
        onBack={handleBack}
        headerClass="entry-header"
        right={
          <button
            className="btn btn-icon"
            onClick={() => { setIsCreating(true); setNewGroupName(''); }}
            title="New group"
            aria-label="New group"
          >
            <PlusIcon />
          </button>
        }
      />

      <div className="group-manager-content screen-scroll-region">
        {error && <div className="error-message" role="alert">{error}</div>}

        {isCreating && (
          <div className="group-create-bar">
            <FolderIcon className="group-create-icon" size={18} />
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
            <button className="btn btn-icon group-create-cancel" onClick={() => { setIsCreating(false); setNewGroupName(''); }} aria-label="Cancel">
              <CloseIcon size={16} />
            </button>
          </div>
        )}

        {state.groups.length === 0 && !isCreating && (
          <div className="empty-state">
            <FolderIcon size={64} />
            <p>No groups yet</p>
            <p className="text-muted-hint">Tap + to create your first group</p>
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
                      <FolderIcon size={18} />
                    </div>
                    <div className="group-card-text">
                      <span className="group-card-name">{g.name}</span>
                      <span className="group-card-count">{groupCount(g.id)} {groupCount(g.id) === 1 ? 'entry' : 'entries'}</span>
                    </div>
                  </div>
                  <div className="group-card-actions">
                    <button className="btn btn-icon group-action-rename" onClick={() => { setEditingId(g.id); setEditingName(g.name); }} title="Rename" aria-label={`Rename ${g.name}`}>
                      <EditIcon size={16} />
                    </button>
                    <button className="btn btn-icon group-action-delete" onClick={() => setDeleteTarget({ id: g.id, name: g.name })} title="Delete" aria-label={`Delete ${g.name}`}>
                      <TrashIcon size={16} />
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
