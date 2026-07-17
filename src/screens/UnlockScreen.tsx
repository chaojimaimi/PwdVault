import { useState } from 'react';
import { useAuth } from '../context/AppContext';

export function UnlockScreen() {
  const { state, actions } = useAuth();
  const [password, setPassword] = useState('');
  const [localError, setLocalError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLocalError(null);

    try {
      const success = await actions.unlock(password);
      if (!success) {
        setLocalError('Invalid password');
      }
    } catch {
      setLocalError('Failed to unlock vault');
    } finally {
      setPassword('');
    }
  };

  const error = localError || state.error;

  return (
    <div className="screen">
      <div className="card">
        <div className="card-header">
          <h1>PwdVault</h1>
          <p>Enter your master password to unlock</p>
        </div>

        {error && <div className="error-message" id="unlock-error" role="alert">{error}</div>}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="password">Master Password</label>
            <input
              id="password"
              type="password"
              className="form-input"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter master password"
              autoFocus
              disabled={state.isLoading}
              aria-invalid={!!error}
              aria-describedby={error ? 'unlock-error' : undefined}
            />
          </div>

          <button
            type="submit"
            className="btn btn-primary"
            disabled={state.isLoading || !password}
          >
            {state.isLoading ? (
              <span className="loading">
                <span className="spinner" />
                Unlocking...
              </span>
            ) : (
              'Unlock'
            )}
          </button>
        </form>
      </div>
    </div>
  );
}
