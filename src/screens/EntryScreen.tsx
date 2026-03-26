import { useState, useEffect } from 'react';
import { useApp } from '../context/AppContext';
import { generatePassword } from '../api/vault';
import type { CreateEntryRequest } from '../types';

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
  });
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tagInput, setTagInput] = useState('');
  const [showGenerator, setShowGenerator] = useState(false);
  const [generatedPassword, setGeneratedPassword] = useState('');

  useEffect(() => {
    if (state.selectedEntry) {
      setFormData({
        title: state.selectedEntry.title,
        url: state.selectedEntry.url || '',
        username: state.selectedEntry.username,
        password: state.selectedEntry.password,
        notes: state.selectedEntry.notes || '',
        tags: state.selectedEntry.tags,
      });
    }
  }, [state.selectedEntry]);

  const handleBack = () => {
    actions.selectEntry(null);
    actions.navigate('vault');
  };

  const handleSave = async () => {
    if (!formData.title || !formData.username || !formData.password) {
      setError('Title, username, and password are required');
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      if (isNew) {
        await actions.createEntry(formData);
      } else if (state.selectedEntry) {
        await actions.updateEntry(state.selectedEntry.id, formData);
      }
      handleBack();
    } catch {
      setError('Failed to save entry');
    } finally {
      setIsLoading(false);
    }
  };

  const handleDelete = async () => {
    if (!state.selectedEntry) return;

    if (!confirm('Are you sure you want to delete this entry?')) return;

    setIsLoading(true);
    try {
      await actions.deleteEntry(state.selectedEntry.id);
      handleBack();
    } catch {
      setError('Failed to delete entry');
    } finally {
      setIsLoading(false);
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

  const handleCopyPassword = () => {
    navigator.clipboard.writeText(formData.password);
  };

  if (showGenerator) {
    return (
      <div className="modal-overlay">
        <div className="modal">
          <div className="modal-header">
            <h3>Generate Password</h3>
            <button className="btn btn-icon" onClick={() => setShowGenerator(false)}>×</button>
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
      <header className="entry-header">
        <button className="btn btn-icon" onClick={handleBack}>
          <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M19 12H5M12 19l-7-7 7-7" />
          </svg>
        </button>
        <h2>{isNew ? 'New Password' : 'Edit Password'}</h2>
        <div style={{ width: '40px' }} />
      </header>

      <div className="entry-content">
        {error && <div className="error-message">{error}</div>}

        <div className="form-group">
          <label>Title *</label>
          <input
            type="text"
            className="form-input"
            value={formData.title}
            onChange={(e) => setFormData({ ...formData, title: e.target.value })}
            placeholder="e.g., Google, GitHub"
          />
        </div>

        <div className="form-group">
          <label>URL</label>
          <input
            type="url"
            className="form-input"
            value={formData.url}
            onChange={(e) => setFormData({ ...formData, url: e.target.value })}
            placeholder="https://example.com"
          />
        </div>

        <div className="form-group">
          <label>Username *</label>
          <input
            type="text"
            className="form-input"
            value={formData.username}
            onChange={(e) => setFormData({ ...formData, username: e.target.value })}
            placeholder="email@example.com"
          />
        </div>

        <div className="form-group">
          <label>Password *</label>
          <div className="password-field field-value">
            <input
              type={showPassword ? 'text' : 'password'}
              value={formData.password}
              onChange={(e) => setFormData({ ...formData, password: e.target.value })}
            />
            <button onClick={() => setShowPassword(!showPassword)} type="button">
              {showPassword ? (
                <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24" />
                  <line x1="1" y1="1" x2="23" y2="23" />
                </svg>
              ) : (
                <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                  <circle cx="12" cy="12" r="3" />
                </svg>
              )}
            </button>
            <button onClick={handleCopyPassword} type="button">
              <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" />
              </svg>
            </button>
            <button onClick={() => setShowGenerator(true)} type="button">
              <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 2v4m0 12v4M4.93 4.93l2.83 2.83m8.48 8.48l2.83 2.83M2 12h4m12 0h4M4.93 19.07l2.83-2.83m8.48-8.48l2.83-2.83" />
              </svg>
            </button>
          </div>
        </div>

        <div className="form-group">
          <label>Notes</label>
          <textarea
            className="form-input"
            value={formData.notes}
            onChange={(e) => setFormData({ ...formData, notes: e.target.value })}
            placeholder="Additional notes..."
            rows={3}
          />
        </div>

        <div className="form-group">
          <label>Tags</label>
          <div className="entry-tags" style={{ marginBottom: '0.5rem' }}>
            {formData.tags.map((tag) => (
              <span key={tag} className="tag" onClick={() => handleRemoveTag(tag)}>
                {tag} ×
              </span>
            ))}
          </div>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <input
              type="text"
              className="form-input"
              value={tagInput}
              onChange={(e) => setTagInput(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleAddTag()}
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
    </div>
  );
}