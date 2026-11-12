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
  if (lower.includes('error when communicating with the native messaging host')) {
    return 'PwdVault browser integration could not start. Update or reinstall the PwdVault desktop app.';
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

// v1.8.4 P2-2: the single classification exit for transport failures that
// arrive WITHOUT the host's structured error_code (browser-runtime
// native-messaging failures carry no response body — sendToApp feeds these
// here). The set must keep recognizing every real transport failure the
// legacy bare substrings in background-native.js caught ("native messaging"
// / "not found" / "timed out" / "connect"): every browser NM loader error
// enumerates "native messaging", and the real "not found"/"connect" texts
// are pinned explicitly below. The two bare substrings themselves are
// deliberately NOT carried — "Entry not found" (a desktop business error)
// matching the old catch is exactly the misclassification this module ends.
const CONNECTION_ERROR_PHRASES = [
  'native messaging',
  'timed out',
  'host not found',
  'host has exited',
  'cannot connect',
  'failed to connect',
  // Review fold: the "disconnected port" family used to match the legacy
  // bare "connect" substring. Unreachable via sendNativeMessage today (the
  // extension never opens a long-lived port), but cheap to keep recognized.
  'disconnected port',
];

export function isConnectionError(message) {
  const lower = String(message || '').toLowerCase();
  return CONNECTION_ERROR_PHRASES.some((phrase) => lower.includes(phrase));
}
