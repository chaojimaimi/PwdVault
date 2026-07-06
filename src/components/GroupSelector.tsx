import { useEffect, useState } from 'react';
import { createGroup, listAllGroups } from '../api/vault';
import type { Group } from '../types';

interface Props {
  value?: string | null;
  onChange: (id: string | null) => void;
}

export default function GroupSelector({ value, onChange }: Props) {
  const [groups, setGroups] = useState<Group[]>([]);
  const [isCreating, setIsCreating] = useState(false);
  const [newGroupName, setNewGroupName] = useState('');
  const [error, setError] = useState<string | null>(null);

  const fetchGroups = async () => {
    try {
      const g = await listAllGroups();
      setGroups(g || []);
    } catch {
      setGroups([]);
    }
  };

  useEffect(() => {
    fetchGroups();
  }, []);

  const handleCreate = async () => {
    const name = newGroupName.trim();
    if (!name) return;
    setError(null);
    try {
      const created = await createGroup(name);
      await fetchGroups();
      onChange(created.id || null);
      setNewGroupName('');
      setIsCreating(false);
    } catch {
      setError('Failed to create group');
    }
  };

  return (
    <div className="group-selector">
      {isCreating ? (
        <div className="group-selector-row">
          <input
            type="text"
            className="form-input"
            value={newGroupName}
            onChange={(e) => setNewGroupName(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleCreate()}
            placeholder="New group name"
            autoFocus
          />
          <button className="btn" onClick={handleCreate} type="button">Add</button>
          <button className="btn btn-secondary" onClick={() => { setIsCreating(false); setNewGroupName(''); setError(null); }} type="button">Cancel</button>
        </div>
      ) : (
        <div className="group-selector-row">
          <select value={value || ''} onChange={(e) => onChange(e.target.value || null)}>
            <option value="">(No group)</option>
            {groups.map((g) => (
              <option key={g.id} value={g.id}>{g.name}</option>
            ))}
          </select>
          <button className="btn btn-link" onClick={() => setIsCreating(true)} type="button">New</button>
        </div>
      )}
      {error && <div className="error-message group-selector-error">{error}</div>}
    </div>
  );
}
