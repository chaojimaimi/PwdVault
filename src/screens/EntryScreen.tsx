import { useState, useEffect } from 'react';
import { useApp } from '../context/AppContext';
import { generatePassword } from '../api/vault';
import { copyWithTimeout } from '../utils/clipboard';
import { showToast } from '../utils/toast';
import { BackHeader } from '../components/BackHeader';
import { StrengthMeter } from '../components/StrengthMeter';
import { EyeIcon, EyeOffIcon, CopyIcon, GenerateIcon } from '../components/Icons';
import ConfirmationModal, { ChangeItem } from '../components/ConfirmationModal';
import DeleteConfirmModal from '../components/DeleteConfirmModal';
import GroupSelector from '../components/GroupSelector';
import type { CreateEntryRequest, EntrySummary } from '../types';

export function EntryScreen() {
  const { state, actions } = useApp();
  const isEditing = !!state.selectedEntry?.id;
  const isNew = !state.selectedEntry;

  const [formData, setFormData] = useState<CreateEntryRequest>({
    title: '',
    url: '',
    username: '',
    password: '',
    notes: '',
    tags: [],
    group_id: null,
  });
  const [originalSecret, setOriginalSecret] = useState<{ password: string; notes: string } | null>(null);
  const [secretLoaded, setSecretLoaded] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tagInput, setTagInput] = useState('');
  const [showGenerator, setShowGenerator] = useState(false);
  const [generatedPassword, setGeneratedPassword] = useState('');
  const [showConfirmation, setShowConfirmation] = useState(false);
  const [pendingChanges, setPendingChanges] = useState<CreateEntryRequest | null>(null);
  const [changesList, setChangesList] = useState<ChangeItem[]>([]);
  const [isSavingConfirmed, setIsSavingConfirmed] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);

  useEffect(() => {
    if (state.selectedEntry) {
      // Fill non-sensitive metadata immediately; secrets are fetched on demand
      // and kept only in this component's state while the user is on this screen.
      setFormData({
        title: state.selectedEntry.title,
        url: state.selectedEntry.url || '',
        username: state.selectedEntry.username,
        password: '',
        notes: '',
        tags: state.selectedEntry.tags,
        group_id: state.selectedEntry.group_id || null,
      });
      setOriginalSecret(null);
      setSecretLoaded(false);

      // Editing an existing entry: load secrets once so the form can be saved
      // with the existing password/notes if unchanged.
      setIsLoading(true);
      actions.getEntrySecret(state.selectedEntry.id)
        .then((secret) => {
          if (secret) {
            setFormData((prev) => ({
              ...prev,
              password: secret.password,
              notes: secret.notes || '',
            }));
            setOriginalSecret({
              password: secret.password,
              notes: secret.notes || '',
            });
          } else {
            setError('Failed to load entry secrets (empty response)');
          }
          setSecretLoaded(true);
        })
        .catch((err) => {
          const msg = typeof err === 'string' ? err
            : err?.message ? err.message
            : (() => { try { return JSON.stringify(err); } catch { return String(err); } })();
          setError(`Failed to load entry secrets: ${msg}`);
          setSecretLoaded(true);
        })
        .finally(() => setIsLoading(false));
    } else {
      setFormData({
        title: '',
        url: '',
        username: '',
        password: '',
        notes: '',
        tags: [],
        group_id: null,
      });
      setOriginalSecret(null);
      setSecretLoaded(false);
    }
  }, [state.selectedEntry]);

  // Clear plaintext secrets from component state as soon as the user leaves
  // the screen, minimizing the time they reside in memory.
  useEffect(() => {
    return () => {
      setFormData((prev) => ({ ...prev, password: '', notes: '' }));
      setOriginalSecret(null);
    };
  }, []);

  const handleBack = () => {
    actions.selectEntry(null);
    actions.navigate('vault');
  };

  const handleSave = async () => {
    if (!formData.title || !formData.username || !formData.password) {
      setError('Title, username, and password are required');
      return;
    }
    setError(null);

    if (isNew) {
      setIsLoading(true);
      try {
        await actions.createEntry(formData);
        handleBack();
      } catch {
        setError('Failed to create entry');
      } finally {
        setIsLoading(false);
      }
      return;
    }

    if (!state.selectedEntry) return;

    const changes = detectChanges(state.selectedEntry, originalSecret, formData);
    if (changes.length === 0) {
      handleBack();
      return;
    }

    setPendingChanges(formData);
    setChangesList(changes);
    setShowConfirmation(true);
  };

  const handleDelete = () => {
    if (!state.selectedEntry) return;
    setShowDeleteConfirm(true);
  };

  const onConfirmDelete = async () => {
    if (!state.selectedEntry) return;
    setIsLoading(true);
    try {
      await actions.deleteEntry(state.selectedEntry.id);
      setShowDeleteConfirm(false);
      handleBack();
    } catch {
      setError('Failed to delete entry');
    } finally {
      setIsLoading(false);
    }
  };

  function detectChanges(
    originalMeta: EntrySummary,
    originalSecret: { password: string; notes: string } | null,
    current: CreateEntryRequest,
  ): ChangeItem[] {
    const changes: ChangeItem[] = [];
    if (originalMeta.title !== current.title) {
      changes.push({ fieldId: 'title', label: 'Title', oldValue: originalMeta.title, newValue: current.title, valueType: 'text' });
    }
    if ((originalMeta.url || '') !== (current.url || '')) {
      changes.push({ fieldId: 'url', label: 'URL', oldValue: originalMeta.url || '', newValue: current.url || '', valueType: 'text' });
    }
    if (originalMeta.username !== current.username) {
      changes.push({ fieldId: 'username', label: 'Username', oldValue: originalMeta.username, newValue: current.username, valueType: 'text' });
    }
    const originalPassword = originalSecret?.password ?? '';
    if (originalPassword !== current.password) {
      changes.push({ fieldId: 'password', label: 'Password', valueType: 'password' });
    }
    const originalNotes = originalSecret?.notes ?? '';
    if (originalNotes !== (current.notes || '')) {
      changes.push({ fieldId: 'notes', label: 'Notes', oldValue: originalNotes.slice(0, 200), newValue: (current.notes || '').slice(0, 200), valueType: 'notes' });
    }
    const origTags = originalMeta.tags || [];
    const added = current.tags.filter((t) => !origTags.includes(t));
    const removed = origTags.filter((t) => !current.tags.includes(t));
    if (added.length || removed.length) {
      changes.push({ fieldId: 'tags', label: 'Tags', oldValue: removed.join(', '), newValue: added.join(', '), valueType: 'tags' });
    }
    if ((originalMeta.group_id || null) !== (current.group_id || null)) {
      changes.push({ fieldId: 'group_id', label: 'Group', oldValue: originalMeta.group_id || '', newValue: current.group_id || '', valueType: 'text' });
    }
    return changes;
  }

  const onConfirmSave = async () => {
    if (!pendingChanges || !state.selectedEntry) return;
    setIsSavingConfirmed(true);
    try {
      await actions.updateEntry(state.selectedEntry.id, pendingChanges);
      setShowConfirmation(false);
      handleBack();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : '';
      setError('Failed to save entry' + (msg ? ': ' + msg : ''));
    } finally {
      setIsSavingConfirmed(false);
    }
  };

  const handleAddTag = () => {
    if (tagInput.trim() && !formData.tags.includes(tagInput.trim())) {
      setFormData({ ...formData, tags: [...formData.tags, tagInput.trim()] });
      setTagInput('');
    }
  };

  const handleRemoveTag = (tag: string) => {
    setFormData({ ...formData, tags: formData.tags.filter((t) => t !== tag) });
  };

  const handleGeneratePassword = async () => {
    try {
      const pwd = await generatePassword({
        length: 16,
        includeUppercase: true,
        includeLowercase: true,
        includeNumbers: true,
        includeSymbols: true,
      });
      setGeneratedPassword(pwd);
    } catch {
      setError('Failed to generate password');
    }
  };

  const handleUseGenerated = () => {
    setFormData({ ...formData, password: generatedPassword });
    setShowGenerator(false);
    setGeneratedPassword('');
  };

  const handleCopyPassword = async () => {
    let password = formData.password;
    if (!password && state.selectedEntry) {
      try {
        const secret = await actions.getEntrySecret(state.selectedEntry.id);
        password = secret?.password || '';
      } catch {
        setError('Failed to copy password');
        return;
      }
    }
    if (!password) return;
    await copyWithTimeout(password);
    showToast('Password copied (auto-clears in 30s)');
  };

  if (showGenerator) {
    return (
      <div className="modal-overlay" role="dialog" aria-modal="true" aria-label="Generate Password">
        <div className="modal">
          <div className="modal-header">
            <h3>Generate Password</h3>
            <button className="btn btn-icon" onClick={() => setShowGenerator(false)} aria-label="Close">
              ×
            </button>
          </div>
          <div className="modal-body">
            <div className="password-preview">
              {generatedPassword || 'Click generate to create a password'}
            </div>
            <button className="btn btn-secondary" onClick={handleGeneratePassword}>
              Generate New
            </button>
          </div>
          <div className="modal-footer">
            <button className="btn btn-secondary" onClick={() => setShowGenerator(false)}>
              Cancel
            </button>
            <button
              className="btn btn-primary"
              onClick={handleUseGenerated}
              disabled={!generatedPassword}
            >
              Use Password
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="entry-screen">
      <BackHeader title={isNew ? 'New Password' : 'Edit Password'} onBack={handleBack} headerClass="entry-header" />

      <div className="entry-content">
        {error && <div className="error-message">{error}</div>}

        <div className="form-group">
          <label htmlFor="entry-title">Title *</label>
          <input
            id="entry-title"
            type="text"
            className="form-input"
            value={formData.title}
            onChange={(e) => setFormData({ ...formData, title: e.target.value })}
            placeholder="e.g., Google, GitHub"
          />
        </div>

        <div className="form-group">
          <label htmlFor="entry-url">URL</label>
          <input
            id="entry-url"
            type="url"
            className="form-input"
            value={formData.url}
            onChange={(e) => setFormData({ ...formData, url: e.target.value })}
            placeholder="https://example.com"
          />
        </div>

        <div className="form-group">
          <label htmlFor="entry-username">Username *</label>
          <input
            id="entry-username"
            type="text"
            className="form-input"
            value={formData.username}
            onChange={(e) => setFormData({ ...formData, username: e.target.value })}
            placeholder="email@example.com"
          />
        </div>

        <div className="form-group">
          <label htmlFor="entry-password">Password *</label>
          <div className="password-field field-value">
            <input
              id="entry-password"
              type={showPassword ? 'text' : 'password'}
              value={formData.password}
              onChange={(e) => setFormData({ ...formData, password: e.target.value })}
              placeholder={isEditing && !secretLoaded ? 'Loading secret…' : ''}
            />
            <button
              onClick={() => setShowPassword(!showPassword)}
              type="button"
              disabled={isEditing && !secretLoaded}
              aria-label={showPassword ? 'Hide password' : 'Show password'}
            >
              {showPassword ? <EyeOffIcon /> : <EyeIcon />}
            </button>
            <button
              onClick={handleCopyPassword}
              type="button"
              disabled={isEditing && !secretLoaded}
              aria-label="Copy password"
            >
              <CopyIcon />
            </button>
            <button onClick={() => setShowGenerator(true)} type="button" aria-label="Generate password">
              <GenerateIcon />
            </button>
          </div>
          <StrengthMeter password={formData.password} />
        </div>

        <div className="form-group">
          <label htmlFor="entry-notes">Notes</label>
          <textarea
            id="entry-notes"
            className="form-input"
            value={formData.notes}
            onChange={(e) => setFormData({ ...formData, notes: e.target.value })}
            placeholder="Additional notes..."
            rows={3}
          />
        </div>

        <div className="form-group">
          <label>Group</label>
          <GroupSelector value={formData.group_id || null} onChange={(id) => setFormData({ ...formData, group_id: id })} />

          <label htmlFor="tag-input" className="tag-label">Tags</label>
          <div className="entry-tags">
            {formData.tags.map((tag) => (
              <span key={tag} className="tag" onClick={() => handleRemoveTag(tag)}>
                {tag} ×
              </span>
            ))}
          </div>
          <div className="tag-input-row">
            <input
              id="tag-input"
              type="text"
              className="form-input"
              value={tagInput}
              onChange={(e) => setTagInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleAddTag()}
              placeholder="Add tag..."
            />
            <button className="btn btn-secondary" onClick={handleAddTag} type="button">
              Add
            </button>
          </div>
        </div>
      </div>

      <div className="entry-actions">
        {isEditing && (
          <button className="btn btn-danger" onClick={handleDelete} disabled={isLoading}>
            Delete
          </button>
        )}
        <button className="btn btn-primary" onClick={handleSave} disabled={isLoading}>
          {isLoading ? 'Saving...' : 'Save'}
        </button>
      </div>

      <ConfirmationModal
        isOpen={showConfirmation}
        changes={changesList}
        onCancel={() => setShowConfirmation(false)}
        onConfirm={onConfirmSave}
        isSaving={isSavingConfirmed}
      />

      <DeleteConfirmModal
        isOpen={showDeleteConfirm}
        message={`Are you sure you want to delete "${state.selectedEntry?.title || 'this entry'}"? This cannot be undone.`}
        onConfirm={onConfirmDelete}
        onCancel={() => setShowDeleteConfirm(false)}
        isDeleting={isLoading}
      />
    </div>
  );
}

export default EntryScreen;
