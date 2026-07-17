export function friendlyConnectionError(error) {
  const message = String(error?.message || error || 'Unknown connection error');
  const lower = message.toLowerCase();
  if (lower.includes('forbidden') || lower.includes('not allowed')) {
    return 'This browser extension is not authorized. Update and restart the PwdVault desktop app.';
  }
  if (lower.includes('host not found') || lower.includes('specified native messaging host')) {
    return 'PwdVault browser integration is not registered. Restart the PwdVault desktop app.';
  }
  if (lower.includes('host has exited')) {
    return 'PwdVault browser integration exited unexpectedly. Restart the desktop app.';
  }
  if (lower.includes('timed out')) {
    return 'PwdVault desktop app did not respond in time.';
  }
  if (lower.includes('cannot connect') || lower.includes('failed to connect')) {
    return 'Cannot reach the PwdVault desktop app. Make sure it is running.';
  }
  return message;
}

export function isAuthenticationError(error) {
  const message = String(error?.message || error || '').toLowerCase();
  return message.includes('unauthorized') || message.includes('invalid token');
}
