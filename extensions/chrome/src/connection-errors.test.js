import { describe, expect, it } from 'vitest';
import { friendlyConnectionError, isAuthenticationError, isConnectionError } from './connection-errors.js';

describe('native connection errors', () => {
  it('distinguishes an unauthorized extension from a stopped desktop app', () => {
    expect(friendlyConnectionError(new Error('Access to the specified native messaging host is forbidden.')))
      .toContain('not authorized');
    expect(friendlyConnectionError(new Error('Cannot connect to desktop app')))
      .toContain('Make sure it is running');
  });

  it('turns Chrome loader failures into an actionable reinstall message', () => {
    expect(friendlyConnectionError(new Error('Error when communicating with the native messaging host.')))
      .toContain('Update or reinstall');
  });

  it('only classifies token rejection as an authentication error', () => {
    expect(isAuthenticationError(new Error('Unauthorized'))).toBe(true);
    expect(isAuthenticationError(new Error('Invalid token'))).toBe(true);
    expect(isAuthenticationError(new Error('Native messaging host timed out'))).toBe(false);
    expect(isAuthenticationError(new Error('Access to host is forbidden'))).toBe(false);
  });

  it('does not classify a desktop business error as a connection failure', () => {
    // v1.8.4 P2-2: the bare "not found" substring in the old sendToApp
    // catch misreported this COMMAND_FAILED message as a dead desktop app.
    expect(isConnectionError('Entry not found')).toBe(false);
    expect(isConnectionError('Vault is locked')).toBe(false);
  });

  it('classifies the real browser transport phrases as connection errors', () => {
    // Superset requirement: every real transport failure the legacy bare
    // substrings caught stays classified after the migration.
    expect(isConnectionError('Specified native messaging host not found')).toBe(true);
    expect(isConnectionError('Native messaging host has exited')).toBe(true);
    expect(isConnectionError('Native messaging host timed out')).toBe(true);
    expect(isConnectionError('Cannot connect to desktop app')).toBe(true);
    expect(isConnectionError('Failed to connect to the PwdVault desktop app')).toBe(true);
  });
});
