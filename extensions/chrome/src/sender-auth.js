const CONTENT_SCRIPT_COMMANDS = new Set([
  'GET_ENTRIES_FOR_URL',
  'GET_ENTRY',
]);

export function classifySender(sender, runtimeId) {
  if (!sender || sender.id !== runtimeId) return 'untrusted';
  if (sender.tab && typeof sender.tab.url === 'string') return 'content';

  if (typeof sender.url === 'string') {
    try {
      const url = new URL(sender.url);
      const isExtensionPage = url.protocol === 'chrome-extension:' || url.protocol === 'moz-extension:';
      if (isExtensionPage && url.pathname.endsWith('/src/popup/popup.html')) return 'popup';
    } catch {
      // Fall through to untrusted.
    }
  }
  return 'untrusted';
}

export function authorizeMessage(message, sender, runtimeId) {
  const senderKind = classifySender(sender, runtimeId);
  if (senderKind === 'popup') return { senderKind, senderUrl: null };
  if (senderKind === 'content' && CONTENT_SCRIPT_COMMANDS.has(message?.type)) {
    // Authorize against the frame URL (sender.url) — the document that
    // actually sent the message. For top-level frames it equals tab.url, and
    // if all_frames is ever enabled the authorization stays on the right
    // frame instead of the top-level page.
    return { senderKind, senderUrl: sender.url || sender.tab.url };
  }
  throw new Error('Message sender is not authorized for this operation');
}

export function normalizedDomain(rawUrl) {
  try {
    return new URL(rawUrl).hostname.toLowerCase().replace(/^www\./, '');
  } catch {
    return null;
  }
}

export function entryMatchesSenderUrl(entry, senderUrl) {
  const senderDomain = normalizedDomain(senderUrl);
  const entryDomain = normalizedDomain(entry?.url);
  return Boolean(senderDomain && entryDomain && senderDomain === entryDomain);
}
