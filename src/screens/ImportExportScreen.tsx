import { useState } from 'react';
import { useApp } from '../context/AppContext';
import { showToast } from '../utils/toast';
import { BackHeader } from '../components/BackHeader';
import { TrashIcon } from '../components/Icons';
import type { VaultBackup } from '../types';

function isTauriEnvironment(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}

export function ImportExportScreen() {
  const { actions } = useApp();
  const [exportPassword, setExportPassword] = useState('');
  const [exportConfirm, setExportConfirm] = useState('');
  const [importPassword, setImportPassword] = useState('');
  const [selectedBackup, setSelectedBackup] = useState<VaultBackup | null>(null);
  const [selectedFileName, setSelectedFileName] = useState('');
  const [exporting, setExporting] = useState(false);
  const [importing, setImporting] = useState(false);
  const [showImportConfirm, setShowImportConfirm] = useState(false);

  const handleBack = () => {
    actions.navigate('settings');
  };

  const handleExport = async () => {
    if (!exportPassword) {
      showToast('Please enter an export password');
      return;
    }
    if (exportPassword.length < 4) {
      showToast('Password must be at least 4 characters');
      return;
    }
    if (exportPassword !== exportConfirm) {
      showToast('Passwords do not match');
      return;
    }

    setExporting(true);
    try {
      const backup = await actions.exportVault(exportPassword);
      const json = JSON.stringify(backup, null, 2);

      if (isTauriEnvironment()) {
        const { save } = await import('@tauri-apps/plugin-dialog');
        const filePath = await save({
          defaultPath: `pwdvault-backup-${new Date().toISOString().slice(0, 10)}.pvault`,
          filters: [{ name: 'PwdVault Backup', extensions: ['pvault'] }],
        });
        if (filePath) {
          const { writeFile } = await import('@tauri-apps/plugin-fs');
          const encoder = new TextEncoder();
          await writeFile(filePath, encoder.encode(json));
          showToast('Backup exported successfully');
        }
      } else {
        const blob = new Blob([json], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `pwdvault-backup-${new Date().toISOString().slice(0, 10)}.pvault`;
        a.click();
        URL.revokeObjectURL(url);
        showToast('Backup exported successfully');
      }

      setExportPassword('');
      setExportConfirm('');
    } catch (error) {
      showToast(error instanceof Error ? error.message : 'Export failed');
    } finally {
      setExporting(false);
    }
  };

  const handleSelectFile = async () => {
    try {
      if (isTauriEnvironment()) {
        const { open } = await import('@tauri-apps/plugin-dialog');
        const filePath = await open({
          filters: [{ name: 'PwdVault Backup', extensions: ['pvault'] }],
          multiple: false,
        });
        if (filePath) {
          const { readFile } = await import('@tauri-apps/plugin-fs');
          const bytes = await readFile(filePath as string);
          const text = new TextDecoder().decode(bytes);
          const backup = JSON.parse(text) as VaultBackup;
          if (backup.version !== 1) {
            showToast('Unsupported backup version');
            return;
          }
          setSelectedBackup(backup);
          setSelectedFileName((filePath as string).split(/[\\/]/).pop() || 'backup.pvault');
        }
      } else {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = '.pvault';
        input.onchange = (e) => {
          const file = (e.target as HTMLInputElement).files?.[0];
          if (file) {
            const reader = new FileReader();
            reader.onload = () => {
              try {
                const backup = JSON.parse(reader.result as string) as VaultBackup;
                if (backup.version !== 1) {
                  showToast('Unsupported backup version');
                  return;
                }
                setSelectedBackup(backup);
                setSelectedFileName(file.name);
              } catch {
                showToast('Invalid backup file');
              }
            };
            reader.readAsText(file);
          }
        };
        input.click();
      }
    } catch (error) {
      showToast(error instanceof Error ? error.message : 'Failed to read file');
    }
  };

  const handleImport = async () => {
    if (!selectedBackup) {
      showToast('Please select a backup file first');
      return;
    }
    if (!importPassword) {
      showToast('Please enter the backup password');
      return;
    }

    setShowImportConfirm(true);
  };

  const confirmImport = async () => {
    setShowImportConfirm(false);
    setImporting(true);
    try {
      const result = await actions.importVault(selectedBackup!, importPassword);
      showToast(`Restored: ${result.entries_imported} entries, ${result.groups_imported} groups`);
      setImportPassword('');
      setSelectedBackup(null);
      setSelectedFileName('');
    } catch (error) {
      showToast(error instanceof Error ? error.message : 'Import failed');
    } finally {
      setImporting(false);
    }
  };

  return (
    <div className="generator-screen">
      <BackHeader title="Backup & Restore" onBack={handleBack} />

      <div className="generator-content">
        <div className="settings-section">
          <h3 className="settings-section-title">Export Backup</h3>
          <p className="settings-hint">Create an encrypted backup of your vault data</p>
          <div className="import-export-fields">
            <input
              type="password"
              className="input-field"
              placeholder="Export password"
              value={exportPassword}
              onChange={(e) => setExportPassword(e.target.value)}
            />
            <input
              type="password"
              className="input-field"
              placeholder="Confirm password"
              value={exportConfirm}
              onChange={(e) => setExportConfirm(e.target.value)}
            />
          </div>
          <button
            className="btn btn-secondary btn-full"
            onClick={handleExport}
            disabled={exporting || !exportPassword || !exportConfirm}
          >
            {exporting ? 'Exporting...' : 'Export Backup'}
          </button>
        </div>

        <div className="settings-divider" />

        <div className="settings-section">
          <h3 className="settings-section-title">Restore Backup</h3>
          <p className="settings-hint">Restore from a previously exported backup file</p>
          <button className="btn btn-secondary btn-full" onClick={handleSelectFile}>
            {selectedFileName ? selectedFileName : 'Select Backup File'}
          </button>
          {selectedBackup && (
            <div className="import-export-fields">
              <input
                type="password"
                className="input-field"
                placeholder="Backup password"
                value={importPassword}
                onChange={(e) => setImportPassword(e.target.value)}
              />
              <button
                className="btn btn-primary btn-full"
                onClick={handleImport}
                disabled={importing || !importPassword}
              >
                {importing ? 'Restoring...' : 'Restore Backup'}
              </button>
            </div>
          )}
        </div>
      </div>

      {showImportConfirm && (
        <div className="modal-overlay" onClick={() => setShowImportConfirm(false)}>
          <div className="confirm-modal" onClick={(e) => e.stopPropagation()}>
            <div className="confirm-modal-header">
              <div className="confirm-modal-icon confirm-modal-icon-danger">
                <TrashIcon size={18} />
              </div>
              <div>
                <h3 className="confirm-modal-title">Restore Backup?</h3>
              </div>
            </div>
            <div className="confirm-modal-body">
              <p className="confirm-delete-message">
                This will replace all current vault data with the backup contents. This action cannot be undone.
              </p>
            </div>
            <div className="confirm-modal-footer">
              <div className="confirm-modal-actions">
                <button className="btn btn-secondary" onClick={() => setShowImportConfirm(false)}>Cancel</button>
                <button className="btn btn-danger" onClick={confirmImport}>Restore</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
