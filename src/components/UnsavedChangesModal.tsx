import { AccessibleDialog } from './AccessibleDialog';

interface Props {
  isOpen: boolean;
  onStay: () => void;
  onDiscard: () => void;
}

export function UnsavedChangesModal({ isOpen, onStay, onDiscard }: Props) {
  return (
    <AccessibleDialog
      isOpen={isOpen}
      onClose={onStay}
      labelledBy="unsaved-title"
      describedBy="unsaved-description"
      initialFocusSelector="[data-dialog-stay]"
    >
        <div className="modal-header"><h3 id="unsaved-title">Discard unsaved changes?</h3></div>
        <div className="modal-body"><p id="unsaved-description">Your changes have not been saved.</p></div>
        <div className="modal-footer">
          <button className="btn btn-secondary" data-dialog-stay onClick={onStay}>Keep editing</button>
          <button className="btn btn-danger" onClick={onDiscard}>Discard</button>
        </div>
    </AccessibleDialog>
  );
}
