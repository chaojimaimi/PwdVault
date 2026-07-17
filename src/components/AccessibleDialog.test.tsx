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
