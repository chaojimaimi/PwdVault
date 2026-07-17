import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, expect, test, vi } from 'vitest';
import EntryScreen from '../EntryScreen';

const getEntrySecret = vi.fn();
const updateEntry = vi.fn().mockResolvedValue({});
const appValue: any = {
  state: {
    selectedEntry: {
      id: 'entry-1', title: 'Before', username: 'user', url: '', tags: [], group_id: null,
      created_at: 1, updated_at: 1,
    },
  },
  actions: {
    getEntrySecret,
    updateEntry,
    selectEntry: vi.fn(),
    navigate: vi.fn(),
    deleteEntry: vi.fn(),
    createEntry: vi.fn(),
  },
};

vi.mock('../../context/AppContext', () => ({ useApp: () => appValue }));
vi.mock('../../components/GroupSelector', () => ({ default: () => <div data-testid="group-selector" /> }));

beforeEach(() => {
  vi.clearAllMocks();
  updateEntry.mockResolvedValue({});
});

test('metadata-only edit neither fetches nor resubmits existing secrets', async () => {
  render(<EntryScreen />);
  expect(getEntrySecret).not.toHaveBeenCalled();

  fireEvent.change(screen.getByLabelText('Title *'), { target: { value: 'After' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save' }));
  fireEvent.click(screen.getByText("I've reviewed these changes"));
  fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }));

  await waitFor(() => expect(updateEntry).toHaveBeenCalledOnce());
  expect(getEntrySecret).not.toHaveBeenCalled();
  const patch = updateEntry.mock.calls[0][1];
  expect(patch).not.toHaveProperty('password');
  expect(patch.update_notes).toBe(false);
});

test('back navigation warns only after the form becomes dirty', () => {
  const { unmount } = render(<EntryScreen />);
  fireEvent.click(screen.getByRole('button', { name: 'Go back' }));
  expect(appValue.actions.navigate).toHaveBeenCalledWith('vault');
  expect(screen.queryByText('Discard unsaved changes?')).not.toBeInTheDocument();
  unmount();

  vi.clearAllMocks();
  render(<EntryScreen />);
  fireEvent.change(screen.getByLabelText('Title *'), { target: { value: 'Changed' } });
  fireEvent.click(screen.getByRole('button', { name: 'Go back' }));
  expect(screen.getByText('Discard unsaved changes?')).toBeInTheDocument();
  expect(appValue.actions.navigate).not.toHaveBeenCalled();
});
