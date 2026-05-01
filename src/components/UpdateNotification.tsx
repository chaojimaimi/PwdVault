import { openUrl } from '@tauri-apps/plugin-opener';
import type { UpdateInfo } from '../types';

interface UpdateNotificationProps {
  updateInfo: UpdateInfo;
  onDismiss: () => void;
}

export function UpdateNotification({ updateInfo, onDismiss }: UpdateNotificationProps) {
  const handleDownload = async () => {
    try {
      await openUrl(updateInfo.download_url);
    } catch {
      // Fallback: window.open as last resort
      window.open(updateInfo.download_url, '_blank');
    }
  };

  const handleDismiss = () => {
    localStorage.setItem('pwdvault_dismissed_update', updateInfo.latest_version);
    onDismiss();
  };

  return (
    <div className="update-notification">
      <div className="update-notification-content">
        <svg className="icon update-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
          <polyline points="7 10 12 15 17 10" />
          <line x1="12" y1="15" x2="12" y2="3" />
        </svg>
        <span className="update-text">PwdVault {updateInfo.latest_version} is available</span>
        <button className="btn btn-sm btn-primary" onClick={handleDownload}>Download</button>
        <button className="btn btn-sm btn-link" onClick={handleDismiss}>Dismiss</button>
      </div>
    </div>
  );
}
