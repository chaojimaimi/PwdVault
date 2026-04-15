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
  title = '确认修改密码条目',
  changes,
  requireTypedConfirm = false,
  onConfirm,
  onCancel,
  isSaving = false,
}: Props) {
  const [checked, setChecked] = React.useState(false);
  const [typed, setTyped] = React.useState('');

  React.useEffect(() => {
    if (!isOpen) {
      setChecked(false);
      setTyped('');
    }
  }, [isOpen]);

  const canConfirm = requireTypedConfirm ? typed === 'CONFIRM' : checked;

  if (!isOpen) return null;

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="confirm-title">
      <div className="modal" style={{maxWidth: 720}}>
        <h2 id="confirm-title">{title}</h2>
        <div className="changes-list" aria-live="polite">
          {changes.map((c) => (
            <div key={c.fieldId} className="change-row" style={{display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid var(--color-border)'}}>
              <div style={{flex: '0 0 140px', fontWeight: 600}}>{c.label}</div>
              <div style={{flex: 1, display: 'flex', alignItems: 'center'}}>
                <div style={{color: 'var(--color-text-muted)', marginRight: 8}}>{c.valueType === 'password' ? '••••••' : (c.oldValue ?? '—')}</div>
                <div style={{margin: '0 8px'}}>→</div>
                <div style={{color: 'var(--color-text)'}}>{c.valueType === 'password' ? '••••••' : (c.newValue ?? '—')}</div>
              </div>
            </div>
          ))}
        </div>

        <div className="confirm-controls" style={{marginTop: 12}}>
          {!requireTypedConfirm ? (
            <label style={{display: 'flex', alignItems: 'center', gap: 8}}>
              <input type="checkbox" checked={checked} onChange={(e) => setChecked(e.target.checked)} />
              <span>我已阅读并确认上述更改</span>
            </label>
          ) : (
            <label>
              在下方输入 <strong>CONFIRM</strong> 以确认：
              <input value={typed} onChange={(e) => setTyped(e.target.value)} style={{display: 'block', marginTop: 8}} />
            </label>
          )}
        </div>

        <div className="modal-actions" style={{display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16}}>
          <button onClick={onCancel} disabled={isSaving}>取消</button>
          <button onClick={() => onConfirm()} disabled={!canConfirm || isSaving} aria-disabled={!canConfirm || isSaving}>
            {isSaving ? '保存中...' : '确认保存'}
          </button>
        </div>
      </div>
    </div>
  );
}

export default ConfirmationModal;
