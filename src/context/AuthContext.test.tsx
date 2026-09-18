import { render, fireEvent, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthProvider, useAuth } from './AuthContext';

// Regression guard for the unlock error contract (H2): every false return
// must surface an error through state.error — either the backend's message
// (rate limit) or the context-written "Invalid password" — and a true return
// must transition to the vault without any error.

const setupVault = vi.fn();
const unlockVault = vi.fn();

vi.mock('../api/vault', () => ({
	setupVault: (...args: unknown[]) => setupVault(...args),
	unlockVault: (...args: unknown[]) => unlockVault(...args),
}));

let unlockResult: boolean | null = null;

function Probe() {
	const { state, actions } = useAuth();
	return (
		<div>
			<span data-testid="error">{state.error ?? ''}</span>
			<span data-testid="screen">{state.screen}</span>
			<span data-testid="unlocked">{String(state.isUnlocked)}</span>
			<button
				type="button"
				onClick={() => {
					void actions.unlock('master-pw').then((r) => {
						unlockResult = r;
					});
				}}
			>
				unlock
			</button>
		</div>
	);
}

beforeEach(() => {
	vi.clearAllMocks();
	unlockResult = null;
	// AuthProvider probes vault initialization on mount.
	setupVault.mockResolvedValue(true);
});

async function renderAndUnlock() {
	render(
		<AuthProvider>
			<Probe />
		</AuthProvider>,
	);
	fireEvent.click(await screen.findByRole('button', { name: 'unlock' }));
	await waitFor(() => expect(unlockResult).not.toBeNull());
}

describe('AuthProvider unlock error contract', () => {
	it('writes "Invalid password" when the backend resolves Ok(false)', async () => {
		// Wrong password: vault.rs resolves Ok(false) — nothing else writes an
		// error, so the context must.
		unlockVault.mockResolvedValue(false);
		await renderAndUnlock();

		expect(unlockResult).toBe(false);
		expect(screen.getByTestId('error')).toHaveTextContent('Invalid password');
		expect(screen.getByTestId('unlocked')).toHaveTextContent('false');
	});

	it('keeps the backend error when unlock rejects (RateLimited path)', async () => {
		// Rate limiting rejects with the serialized VaultError — the catch
		// branch writes it, and "Invalid password" must not override it.
		unlockVault.mockRejectedValue({ RateLimited: { retry_after_secs: 42 } });
		await renderAndUnlock();

		expect(unlockResult).toBe(false);
		expect(screen.getByTestId('error')).toHaveTextContent('RateLimited');
		expect(screen.getByTestId('error')).not.toHaveTextContent(
			'Invalid password',
		);
	});

	it('transitions to the vault without an error on success', async () => {
		unlockVault.mockResolvedValue(true);
		await renderAndUnlock();

		expect(unlockResult).toBe(true);
		expect(screen.getByTestId('error')).toHaveTextContent('');
		expect(screen.getByTestId('screen')).toHaveTextContent('vault');
		expect(screen.getByTestId('unlocked')).toHaveTextContent('true');
	});
});
