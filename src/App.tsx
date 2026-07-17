import { useEffect } from 'react';
import { listen } from '@tauri-apps/api/event';
import { AppProvider, useApp } from './context/AppContext';
import { SetupScreen } from './screens/SetupScreen';
import { UnlockScreen } from './screens/UnlockScreen';
import { VaultScreen } from './screens/VaultScreen';
import { EntryScreen } from './screens/EntryScreen';
import { GeneratorScreen } from './screens/GeneratorScreen';
import GroupManager from './screens/GroupManager';
import { SettingsScreen } from './screens/SettingsScreen';
import { ImportExportScreen } from './screens/ImportExportScreen';
import { ThemeProvider } from './components/ThemeProvider';
import { showPairingCodeToast } from './utils/toast';
import './styles/themes.css';
import './styles/base.css';
import './styles/components.css';
import './styles/screens.css';
import './styles/vault.css';
import './styles/groups.css';
import './styles/settings.css';

function AppContent() {
  const { state, actions } = useApp();

  if (state.isLoading) {
    return (
      <div className="screen">
        <div className="loading">
          <span className="spinner" />
          <span>Loading...</span>
        </div>
      </div>
    );
  }

  if (state.bootError) {
    return (
      <div className="screen">
        <div className="fatal-error" role="alert">
          <h1>PwdVault could not start</h1>
          <p>{state.bootError}</p>
          <button className="btn btn-primary" onClick={() => void actions.retryBoot()}>
            Retry
          </button>
        </div>
      </div>
    );
  }

  switch (state.screen) {
    case 'setup':
      return <SetupScreen />;
    case 'unlock':
      return <UnlockScreen />;
    case 'vault':
      return <VaultScreen />;
    case 'entry':
      return <EntryScreen />;
    case 'generator':
      return <GeneratorScreen />;
    case 'groupManager':
      return <GroupManager />;
    case 'settings':
      return <SettingsScreen />;
    case 'importExport':
      return <ImportExportScreen />;
    default:
      return <UnlockScreen />;
  }
}

function App() {
  useEffect(() => {
    // Show the pairing code as a non-blocking toast. A modal dialog would
    // block subsequent pair-request events (each one creates a new session
    // and overwrites the previous code), making "Get New Code" in the
    // extension appear to do nothing until the user dismisses the dialog.
    // Toasts let multiple updates show in sequence without blocking.
    const unlisten = listen('pair-request', (event) => {
      const code = event.payload as string;
      // V4 双主题配对码 toast：30s 与后端 SESSION_TTL 保持一致，
      // 确保用户看到的码在有效期内。
      showPairingCodeToast(code, 30000);
    });
    return () => {
      unlisten.then((u) => u());
    };
  }, []);

  return (
    <ThemeProvider>
      <AppProvider>
        <AppContent />
      </AppProvider>
    </ThemeProvider>
  );
}

export default App;
