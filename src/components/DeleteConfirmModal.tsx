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
    <div className="modal-backdrop" role="dialog" aria-modal="true">
      <div className="modal" style={{ maxWidth: 400 }}>
        <h2 style={{ fontSize: '1.1rem', marginBottom: '0.75rem' }}>Confirm Delete</h2>
        <p style={{ marginBottom: '1rem', color: 'var(--color-text-secondary)' }}>{message}</p>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
          <button className="btn btn-secondary" onClick={onCancel} disabled={isDeleting}>Cancel</button>
          <button className="btn btn-danger" onClick={onConfirm} disabled={isDeleting}>
            {isDeleting ? 'Deleting...' : 'Delete'}
          </button>
        </div>
      </div>
    </div>
  );
}
