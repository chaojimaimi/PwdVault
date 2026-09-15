import { useState } from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { AccessibleDialog } from './AccessibleDialog';

function Harness() {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button onClick={() => setOpen(true)}>Open dialog</button>
      <AccessibleDialog
        isOpen={open}
        onClose={() => setOpen(false)}
        labelledBy="test-dialog-title"
        initialFocusSelector="[data-first]"
      >
        <h2 id="test-dialog-title">Test dialog</h2>
        <button data-first>First</button>
        <button>Last</button>
      </AccessibleDialog>
    </>
  );
}

describe('AccessibleDialog', () => {
  it('traps focus, closes on Escape, and restores the trigger focus', async () => {
    const root = document.createElement('div');
    root.id = 'root';
    document.body.appendChild(root);
    render(<Harness />, { container: root });

    const trigger = screen.getByRole('button', { name: 'Open dialog' });
    trigger.focus();
    fireEvent.click(trigger);

    const dialog = await screen.findByRole('dialog', { name: 'Test dialog' });
    const first = screen.getByRole('button', { name: 'First' });
    const last = screen.getByRole('button', { name: 'Last' });
    await waitFor(() => expect(first).toHaveFocus());
    expect(root).toHaveAttribute('inert');

    last.focus();
    fireEvent.keyDown(document, { key: 'Tab' });
    expect(first).toHaveFocus();

    first.focus();
    fireEvent.keyDown(document, { key: 'Tab', shiftKey: true });
    expect(last).toHaveFocus();

    fireEvent.keyDown(document, { key: 'Escape' });
    await waitFor(() => expect(dialog).not.toBeInTheDocument());
    expect(trigger).toHaveFocus();
    expect(root).not.toHaveAttribute('inert');
    root.remove();
  });
});

// A8: stacked dialogs must coordinate through the module-level refcount and
// Escape stack — closing an inner dialog keeps the background inert, and
// one Escape press closes only the topmost dialog.
function StackedHarness() {
  const [openOuter, setOpenOuter] = useState(false);
  const [openInner, setOpenInner] = useState(false);
  return (
    <>
      <button onClick={() => setOpenOuter(true)}>Open outer</button>
      <AccessibleDialog
        isOpen={openOuter}
        onClose={() => setOpenOuter(false)}
        labelledBy="outer-title"
        initialFocusSelector="[data-outer-first]"
      >
        <h2 id="outer-title">Outer dialog</h2>
        <button data-outer-first onClick={() => setOpenInner(true)}>
          Open inner
        </button>
        <button onClick={() => setOpenOuter(false)}>Close outer</button>
      </AccessibleDialog>
      <AccessibleDialog
        isOpen={openInner}
        onClose={() => setOpenInner(false)}
        labelledBy="inner-title"
        initialFocusSelector="[data-inner-first]"
      >
        <h2 id="inner-title">Inner dialog</h2>
        <button data-inner-first onClick={() => setOpenInner(false)}>
          Close inner
        </button>
      </AccessibleDialog>
    </>
  );
}

function mountStackedHarness() {
  const root = document.createElement('div');
  root.id = 'root';
  document.body.appendChild(root);
  render(<StackedHarness />, { container: root });
  return root;
}

describe('AccessibleDialog stacking (A8)', () => {
  it('keeps #root inert when only the inner dialog of a stack closes', async () => {
    const root = mountStackedHarness();

    fireEvent.click(screen.getByRole('button', { name: 'Open outer' }));
    await screen.findByRole('dialog', { name: 'Outer dialog' });
    expect(root).toHaveAttribute('inert');

    fireEvent.click(await screen.findByRole('button', { name: 'Open inner' }));
    await screen.findByRole('dialog', { name: 'Inner dialog' });
    expect(root).toHaveAttribute('inert');

    // Close the INNER dialog via its button (not Escape): the outer dialog
    // is still open, so the background must stay inert.
    fireEvent.click(screen.getByRole('button', { name: 'Close inner' }));
    await waitFor(() =>
      expect(screen.queryByRole('dialog', { name: 'Inner dialog' })).not.toBeInTheDocument(),
    );
    expect(screen.getByRole('dialog', { name: 'Outer dialog' })).toBeInTheDocument();
    expect(root).toHaveAttribute('inert');

    // Last dialog closes: the background becomes interactive again.
    fireEvent.click(screen.getByRole('button', { name: 'Close outer' }));
    await waitFor(() =>
      expect(screen.queryByRole('dialog', { name: 'Outer dialog' })).not.toBeInTheDocument(),
    );
    expect(root).not.toHaveAttribute('inert');
    root.remove();
  });

  it('closes only the topmost dialog per Escape press', async () => {
    const root = mountStackedHarness();

    fireEvent.click(screen.getByRole('button', { name: 'Open outer' }));
    await screen.findByRole('dialog', { name: 'Outer dialog' });

    fireEvent.click(screen.getByRole('button', { name: 'Open inner' }));
    await screen.findByRole('dialog', { name: 'Inner dialog' });

    // First Escape: only the inner (topmost) dialog closes.
    fireEvent.keyDown(document, { key: 'Escape' });
    await waitFor(() =>
      expect(screen.queryByRole('dialog', { name: 'Inner dialog' })).not.toBeInTheDocument(),
    );
    expect(screen.getByRole('dialog', { name: 'Outer dialog' })).toBeInTheDocument();
    expect(root).toHaveAttribute('inert');

    // Second Escape: now the outer dialog closes.
    fireEvent.keyDown(document, { key: 'Escape' });
    await waitFor(() =>
      expect(screen.queryByRole('dialog', { name: 'Outer dialog' })).not.toBeInTheDocument(),
    );
    expect(root).not.toHaveAttribute('inert');
    root.remove();
  });
});

// X3: two dialogs closed in reverse mount order (outer first, inner last).
// The last-closing dialog must restore the ORIGINAL background state, not the
// outer dialog's own `aria-hidden "true"` that it observed at mount. B is
// opened from inside A (portals render outside #root, so their controls stay
// reachable while #root is aria-hidden).
function OutOfOrderHarness() {
  const [openA, setOpenA] = useState(false);
  const [openB, setOpenB] = useState(false);
  return (
    <>
      <button onClick={() => setOpenA(true)}>Open A</button>
      <AccessibleDialog
        isOpen={openA}
        onClose={() => setOpenA(false)}
        labelledBy="dialog-a-title"
      >
        <h2 id="dialog-a-title">Dialog A</h2>
        <button onClick={() => setOpenB(true)}>Open B</button>
        <button onClick={() => setOpenA(false)}>Close A</button>
      </AccessibleDialog>
      <AccessibleDialog
        isOpen={openB}
        onClose={() => setOpenB(false)}
        labelledBy="dialog-b-title"
      >
        <h2 id="dialog-b-title">Dialog B</h2>
        <button onClick={() => setOpenB(false)}>Close B</button>
      </AccessibleDialog>
    </>
  );
}

describe('AccessibleDialog out-of-order close (X3)', () => {
  it('leaves no aria-hidden residue on #root when the outer dialog closes first', async () => {
    const root = document.createElement('div');
    root.id = 'root';
    document.body.appendChild(root);
    render(<OutOfOrderHarness />, { container: root });

    fireEvent.click(screen.getByRole('button', { name: 'Open A' }));
    await screen.findByRole('dialog', { name: 'Dialog A' });
    expect(root).toHaveAttribute('aria-hidden', 'true');

    fireEvent.click(screen.getByRole('button', { name: 'Open B' }));
    await screen.findByRole('dialog', { name: 'Dialog B' });

    // Close A (the background-hiding owner) FIRST; the background must stay
    // hidden while B is still open.
    fireEvent.click(screen.getByRole('button', { name: 'Close A' }));
    await waitFor(() =>
      expect(screen.queryByRole('dialog', { name: 'Dialog A' })).not.toBeInTheDocument(),
    );
    expect(root).toHaveAttribute('aria-hidden', 'true');

    // Close B last: the owner's snapshot (no aria-hidden before any dialog)
    // must be restored — no residue from B's mount-time observation.
    fireEvent.click(screen.getByRole('button', { name: 'Close B' }));
    await waitFor(() =>
      expect(screen.queryByRole('dialog', { name: 'Dialog B' })).not.toBeInTheDocument(),
    );
    expect(root).not.toHaveAttribute('aria-hidden');
    expect(root).not.toHaveAttribute('inert');
    root.remove();
  });
});
