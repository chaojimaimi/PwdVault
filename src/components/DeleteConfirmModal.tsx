interface Props {
  isOpen: boolean;
  message: string;
  onConfirm: () => void;
  onCancel: () => void;
  isDeleting?: boolean;
}

export default function DeleteConfirmModal({ isOpen, message, onConfirm, onCancel, isDeleting = false }: Props) {
  if (!isOpen) return null;

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true">
      <div className="confirm-modal">
        <div className="confirm-modal-header">
          <div className="confirm-modal-icon confirm-modal-icon-danger">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polyline points="3,6 5,6 21,6" />
              <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2" />
              <line x1="10" y1="11" x2="10" y2="17" />
              <line x1="14" y1="11" x2="14" y2="17" />
            </svg>
          </div>
          <div>
            <h3 className="confirm-modal-title">Confirm Delete</h3>
            <p className="confirm-modal-subtitle">This action cannot be undone</p>
          </div>
        </div>

        <div className="confirm-modal-body">
          <p className="confirm-delete-message">{message}</p>
        </div>

        <div className="confirm-modal-footer">
          <div className="confirm-modal-actions">
            <button className="btn btn-secondary" onClick={onCancel} disabled={isDeleting}>
              Cancel
            </button>
            <button className="btn btn-danger" onClick={onConfirm} disabled={isDeleting}>
              {isDeleting ? (
                <span className="loading">
                  <span className="spinner" />
                  Deleting...
                </span>
              ) : (
                'Delete'
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
