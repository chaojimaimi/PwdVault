import { describe, expect, it } from 'vitest';
import { friendlyConnectionError, isAuthenticationError } from './connection-errors.js';

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
});
