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
  // Empty entryUrl is REJECTED here — INTENTIONALLY different from
  // entryMatchesPageUrl below (which allows generic entries on an explicit
  // popup fill): the content-script path auto-fills without a per-entry user
  // click, so a stored URL must exist to compare against the sender frame.
  const rawEntryUrl = typeof entry?.url === 'string' ? entry.url : '';
  if (!senderDomain || !rawEntryUrl) return false;
  // Entries are often stored scheme-less ("github.com/acme"); pad https://
  // exactly like entryMatchesPageUrl before parsing, otherwise such entries
  // would be invisible to the content-script path while the popup could
  // still fill them — a pointless semantics split.
  const withScheme = /^https?:\/\//i.test(rawEntryUrl)
    ? rawEntryUrl
    : `https://${rawEntryUrl}`;
  const entryDomain = normalizedDomain(withScheme);
  return Boolean(entryDomain) && entryDomain === senderDomain;
}

// Single source of truth for "may this entry be filled on this page?".
// Compares normalized domains (lowercase + strip a leading "www."), matching
// the semantics of entryMatchesSenderUrl and background getEntriesForUrl.
// DIVERGENCE IS INTENTIONAL: entryMatchesSenderUrl rejects an empty entryUrl
// (see its comment); this function allows it — an explicit popup fill is a
// deliberate user action on a generic entry. Do NOT "unify" the two.
// NOTE: content.js carries a verbatim copy of this function — content scripts
// are classic scripts and cannot import ES modules. Keep the two copies
// byte-identical; the guard test in sender-auth.test.js enforces it.
export function entryMatchesPageUrl(entryUrl, pageUrl) {
  // Empty entryUrl = generic entry (no stored URL); an explicit popup fill is
  // a deliberate user action, so allow it. Empty pageUrl = cannot judge.
  if (!entryUrl) return true;
  if (!pageUrl) return false;
  // Entries are often stored scheme-less ("github.com/acme"); pad https://
  // exactly like popup.js formatUrl before parsing, otherwise such entries
  // would be rejected here despite being fillable nowhere else.
  const withScheme = /^https?:\/\//i.test(entryUrl)
    ? entryUrl
    : `https://${entryUrl}`;
  const entryDomain = normalizedDomain(withScheme);
  const pageDomain = normalizedDomain(pageUrl);
  // A parse failure yields null (cannot judge) → reject.
  return Boolean(entryDomain && pageDomain && entryDomain === pageDomain);
}
