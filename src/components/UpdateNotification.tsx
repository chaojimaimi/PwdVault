import type { UpdatePhase } from '../context/SettingsContext';

interface UpdateNotificationProps {
  version: string;
  phase: UpdatePhase;
  /** Download progress 0-100 (only rendered while downloading). */
  progress: number;
  onUpdate: () => void;
  onRelaunch: () => void;
  onDismiss: () => void;
}

/**
 * Update banner driven by the signed updater feed (Phase AU). One component
 * covers the whole lifecycle: "Update now" → download progress → "Relaunch".
 * macOS needs the explicit relaunch; on Windows the NSIS installer exits the
 * app by itself, so the Relaunch state is usually never seen there.
 */
export function UpdateNotification({ version, phase, progress, onUpdate, onRelaunch, onDismiss }: UpdateNotificationProps) {
  return (
    <div className="update-notification" role="status">
      <div className="update-notification-content">
        <svg className="icon update-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
          <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
          <polyline points="7 10 12 15 17 10" />
          <line x1="12" y1="15" x2="12" y2="3" />
        </svg>
        <span className="update-text">PwdVault {version} is available</span>
        {phase === 'available' && (
          <button className="btn btn-sm btn-primary" onClick={onUpdate}>Update now</button>
        )}
        {phase === 'ready' && (
          <button className="btn btn-sm btn-primary" onClick={onRelaunch}>Relaunch</button>
        )}
        {phase === 'available' && (
          <button className="btn btn-sm btn-link" onClick={onDismiss}>Dismiss</button>
        )}
      </div>
      {phase === 'downloading' && (
        <div
          className="update-progress"
          role="progressbar"
          aria-label="Downloading update"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={progress}
        >
          <div className="update-progress-bar" style={{ width: `${progress}%` }} />
        </div>
      )}
    </div>
  );
}
