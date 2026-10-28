import { useEffect, useState } from 'react';
import { useVault } from '../context/VaultContext';

interface Props {
  value?: string | null;
  onChange: (id: string | null) => void;
}

export default function GroupSelector({ value, onChange }: Props) {
  const { state, actions } = useVault();
  const [isCreating, setIsCreating] = useState(false);
  const [newGroupName, setNewGroupName] = useState('');
  const [error, setError] = useState<string | null>(null);

  // H4: explicit deps. The 'idle' guard makes re-runs no-ops: once a load
  // starts, status leaves 'idle', and `actions` getting a new identity after
  // a group switch cannot trigger a duplicate fetch either.
  useEffect(() => {
    if (state.groupsStatus === 'idle') void actions.loadGroups().catch(() => undefined);
  }, [state.groupsStatus, actions]);

  const handleCreate = async () => {
    const name = newGroupName.trim();
    if (!name) return;
    setError(null);
    try {
      const created = await actions.createGroup(name);
      onChange(created.id || null);
      setNewGroupName('');
      setIsCreating(false);
    } catch {
      setError('Failed to create group');
    }
  };

  return (
    <div className="group-selector">
      <label htmlFor={isCreating ? 'new-group-name' : 'entry-group'}>Group</label>
      {isCreating ? (
        <div className="group-selector-row">
          <input
            id="new-group-name"
            type="text"
            className="form-input"
            value={newGroupName}
            onChange={(e) => setNewGroupName(e.target.value)}
            onKeyDown={(e) => {
              // preventDefault: this input is rendered inside the entry form,
              // so an unprevented Enter would create the group AND run the
              // form's implicit submission in one keystroke.
              if (e.key === 'Enter') {
                e.preventDefault();
                void handleCreate();
              }
            }}
            placeholder="New group name"
            ref={(el) => {
              // jsx-a11y/no-autofocus: focus at commit when the inline input
              // mounts — same UX as autoFocus, programmatic.
              el?.focus();
            }}
          />
          <button className="btn btn-inline" onClick={handleCreate} type="button">Add</button>
          <button className="btn btn-secondary btn-inline" onClick={() => { setIsCreating(false); setNewGroupName(''); setError(null); }} type="button">Cancel</button>
        </div>
      ) : (
        <div className="group-selector-row">
          <select id="entry-group" className="form-input" value={value || ''} onChange={(e) => onChange(e.target.value || null)}>
            <option value="">(No group)</option>
            {state.groups.map((g) => (
              <option key={g.id} value={g.id}>{g.name}</option>
            ))}
          </select>
          <button className="btn btn-link btn-inline" onClick={() => setIsCreating(true)} type="button">New</button>
        </div>
      )}
      {state.groupsStatus === 'error' && (
        <div className="error-message group-selector-error">
          Could not load groups. <button className="btn btn-link btn-block" type="button" onClick={() => void actions.loadGroups()}>Retry</button>
        </div>
      )}
      {error && <div className="error-message group-selector-error">{error}</div>}
    </div>
  );
}
