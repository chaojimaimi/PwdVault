import { useEffect, useRef, type ReactNode } from 'react';
import { createPortal } from 'react-dom';

const FOCUSABLE = [
  'button:not([disabled])',
  '[href]',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',');

// A8: module-level coordination between stacked dialog instances.
// `openCount` keeps the background inert until the LAST dialog closes;
// `escapeStack` makes Escape close only the topmost (last registered) dialog.
// X3: `snapshot` records the pre-dialog background aria-hidden state and the
// focused element exactly once, owned by the instance that opened while
// `openCount === 0` (the one that sets the background inert). Per-instance
// snapshots would go stale on out-of-order closes: an inner dialog mounted
// after the outer one would snapshot the outer dialog's own `aria-hidden
// "true"` and later "restore" it, leaving the whole app invisible to screen
// readers.
let openCount = 0;
const escapeStack: symbol[] = [];
let snapshot: { ariaHidden: string | null; focused: HTMLElement | null } | null =
  null;

interface Props {
  isOpen: boolean;
  onClose: () => void;
  labelledBy: string;
  describedBy?: string;
  children: ReactNode;
  className?: string;
  initialFocusSelector?: string;
  closeOnOverlay?: boolean;
}

export function AccessibleDialog({
  isOpen,
  onClose,
  labelledBy,
  describedBy,
  children,
  className = 'modal',
  initialFocusSelector,
  closeOnOverlay = true,
}: Props) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  useEffect(() => {
    if (!isOpen) return;
    const root = document.getElementById('root');
    const dialogId = Symbol('accessible-dialog');
    escapeStack.push(dialogId);
    // X3: only the instance that opens on a clean count (the owner) takes the
    // snapshot; inner dialogs must not overwrite it, otherwise an
    // out-of-order close would restore the outer dialog's own background
    // state instead of the original one.
    if (openCount === 0) {
      snapshot = {
        ariaHidden: root?.getAttribute('aria-hidden') ?? null,
        focused:
          document.activeElement instanceof HTMLElement
            ? document.activeElement
            : null,
      };
    }
    openCount += 1;
    // Only the FIRST dialog makes the background inert; stacked dialogs keep
    // it inert until the last one unmounts.
    if (openCount === 1) {
      root?.setAttribute('inert', '');
      root?.setAttribute('aria-hidden', 'true');
    }

    const focusInitial = () => {
      const dialog = dialogRef.current;
      if (!dialog) return;
      const preferred = initialFocusSelector
        ? dialog.querySelector<HTMLElement>(initialFocusSelector)
        : null;
      (preferred || dialog.querySelector<HTMLElement>(FOCUSABLE) || dialog).focus();
    };
    const frame = requestAnimationFrame(focusInitial);

    const handleKeyDown = (event: KeyboardEvent) => {
      const dialog = dialogRef.current;
      if (!dialog) return;
      if (event.key === 'Escape') {
        // Only the topmost dialog responds, so one Escape closes one dialog.
        if (escapeStack[escapeStack.length - 1] !== dialogId) return;
        event.preventDefault();
        onCloseRef.current();
        return;
      }
      if (event.key !== 'Tab') return;
      const focusable = Array.from(dialog.querySelectorAll<HTMLElement>(FOCUSABLE));
      if (focusable.length === 0) {
        event.preventDefault();
        dialog.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener('keydown', handleKeyDown);

    return () => {
      cancelAnimationFrame(frame);
      document.removeEventListener('keydown', handleKeyDown);
      openCount -= 1;
      const stackIndex = escapeStack.indexOf(dialogId);
      if (stackIndex !== -1) escapeStack.splice(stackIndex, 1);
      // X3: restore background interactivity, the original aria-hidden value,
      // and focus ONLY when the last dialog closes and the snapshot exists
      // (i.e. this instance is the owner). Closing an inner dialog of a
      // stack must leave all three untouched.
      if (openCount === 0 && snapshot) {
        root?.removeAttribute('inert');
        if (snapshot.ariaHidden == null) root?.removeAttribute('aria-hidden');
        else root?.setAttribute('aria-hidden', snapshot.ariaHidden);
        snapshot.focused?.focus();
        snapshot = null;
      }
    };
  }, [isOpen, initialFocusSelector]);

  if (!isOpen) return null;

  return createPortal(
    <div
      className="modal-overlay"
      onMouseDown={(event) => {
        if (closeOnOverlay && event.target === event.currentTarget) onClose();
      }}
    >
      <div
        ref={dialogRef}
        className={className}
        role="dialog"
        aria-modal="true"
        aria-labelledby={labelledBy}
        aria-describedby={describedBy}
        tabIndex={-1}
      >
        {children}
      </div>
    </div>,
    document.body,
  );
}
