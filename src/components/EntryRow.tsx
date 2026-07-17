import { memo } from 'react';
import { CopyIcon, UserIcon } from './Icons';
import type { EntrySummary } from '../types';

function getInitials(title: string): string {
  return title.charAt(0).toUpperCase();
}

interface EntryRowProps {
  entry: EntrySummary;
  copied: boolean;
  onOpen: (entry: EntrySummary) => void;
  onCopyUsername: (username: string) => void;
  onCopyPassword: (entry: EntrySummary) => void;
}

/**
 * A single vault entry row. Extracted and memoized (§5.6.1) so that the
 * virtualized list does not re-render unchanged rows on every keystroke or
 * when an unrelated row's copy state changes.
 */
export const EntryRow = memo(function EntryRow({
  entry,
  copied,
  onOpen,
  onCopyUsername,
  onCopyPassword,
}: EntryRowProps) {
  return (
    <div className="entry-item" role="listitem">
      <button
        className="entry-main"
        onClick={() => onOpen(entry)}
        aria-label={`Open ${entry.title}, ${entry.username}`}
      >
        <span className="entry-icon" aria-hidden="true">{getInitials(entry.title)}</span>
        <span className="entry-info">
          <span className="entry-title">{entry.title}</span>
          <span className="entry-username">{entry.username}</span>
        </span>
      </button>
      <div className="entry-actions-inline">
        <button
          className="btn btn-icon btn-copy"
          onClick={() => onCopyUsername(entry.username)}
          title="Copy username"
          aria-label={`Copy username for ${entry.title}`}
        >
          <UserIcon />
        </button>
        <button
          className={`btn btn-icon btn-copy ${copied ? 'copied' : ''}`}
          onClick={() => onCopyPassword(entry)}
          title={copied ? 'Copied!' : 'Copy password'}
          aria-label={`Copy password for ${entry.title}`}
        >
          <CopyIcon />
        </button>
      </div>
    </div>
  );
});
