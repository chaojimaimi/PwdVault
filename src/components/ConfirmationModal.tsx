import React from 'react';

export interface ChangeItem {
  fieldId: string;
  label: string;
  oldValue?: string;
  newValue?: string;
  valueType?: 'text' | 'password' | 'tags' | 'notes';
}

interface Props {
  isOpen: boolean;
  title?: string;
  changes: ChangeItem[];
  requireTypedConfirm?: boolean;
  onConfirm: () => Promise<void> | void;
  onCancel: () => void;
  isSaving?: boolean;
}

export function ConfirmationModal({
  isOpen,
  title = 'Confirm Changes',
  changes,
  onConfirm,
  onCancel,
  isSaving = false,
}: Props) {
  const [checked, setChecked] = React.useState(false);

  React.useEffect(() => {
    if (!isOpen) {
      setChecked(false);
    }
  }, [isOpen]);

  if (!isOpen) return null;

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true">
      <div className="confirm-modal">
        <div className="confirm-modal-header">
          <div className="confirm-modal-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 20h9M16.5 3.5a2.121 2.121 0 013 3L7 19l-4 1 1-4L16.5 3.5z" />
            </svg>
          </div>
          <div>
            <h3 className="confirm-modal-title">{title}</h3>
            <p className="confirm-modal-subtitle">{changes.length} {changes.length === 1 ? 'change' : 'changes'} to review</p>
          </div>
        </div>

        <div className="confirm-changes-list">
          {changes.map((c) => (
            <div key={c.fieldId} className="confirm-change-item">
              <span className="confirm-change-label">{c.label}</span>
              <div className="confirm-change-diff">
                <span className="confirm-change-old">
                  {c.valueType === 'password' ? '••••••••' : (c.oldValue || '—')}
                </span>
                <svg className="confirm-change-arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M5 12h14M12 5l7 7-7 7" />
                </svg>
                <span className="confirm-change-new">
                  {c.valueType === 'password' ? '••••••••' : (c.newValue || '—')}
                </span>
              </div>
            </div>
          ))}
        </div>

        <div className="confirm-modal-footer">
          <label className="confirm-checkbox">
            <input
              type="checkbox"
              checked={checked}
              onChange={(e) => setChecked(e.target.checked)}
            />
            <span>I've reviewed these changes</span>
          </label>
          <div className="confirm-modal-actions">
            <button className="btn btn-secondary" onClick={onCancel} disabled={isSaving}>
              Cancel
            </button>
            <button
              className="btn btn-primary confirm-save-btn"
              onClick={() => onConfirm()}
              disabled={!checked || isSaving}
            >
              {isSaving ? (
                <span className="loading">
                  <span className="spinner" />
                  Saving...
                </span>
              ) : (
                'Save Changes'
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default ConfirmationModal;
