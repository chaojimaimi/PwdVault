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
import './styles/themes.css';
import './styles/App.css';

function AppContent() {
  const { state } = useApp();

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
  return (
    <ThemeProvider>
      <AppProvider>
        <AppContent />
      </AppProvider>
    </ThemeProvider>
  );
}

export default App;
