import React from 'react';
import { render, fireEvent, screen, waitFor } from '@testing-library/react';
import { vi, afterEach, describe, it, expect } from 'vitest';
// Top-level mock for AppContext so we can control `useApp` per-test
let currentAppValue: any = null;
vi.mock('../../context/AppContext', () => ({
  AppContext: { Provider: ({ children }: any) => children },
  useApp: () => currentAppValue,
}));
// Note: import AppContext dynamically inside tests to avoid import-time binding issues

const groups = [
  { id: 'g1', name: 'Work', created_at: 1, updated_at: 1 },
  { id: 'g2', name: 'Personal', created_at: 1, updated_at: 1 },
];

const loadGroups = vi.fn();
const createGroup = vi.fn();
const updateGroup = vi.fn();
const deleteGroup = vi.fn();

// GroupManager will be dynamically imported inside each test after mocking

afterEach(() => {
  vi.resetAllMocks();
  currentAppValue = null;
});

describe('GroupManager', () => {
  it('renders groups and calls createGroup via inline input', async () => {
    const appValue = {
      state: {
        screen: 'groupManager',
        isInitialized: true,
        isUnlocked: true,
        entries: [],
        groups,
        selectedGroupId: null,
        selectedEntry: null,
        searchQuery: '',
        isLoading: false,
        error: null,
      },
      dispatch: () => {},
      actions: { loadGroups, createGroup, updateGroup, deleteGroup, initialize: async () => {}, unlock: async () => true, lock: () => {}, loadEntries: async () => {}, updateEntry: async () => ({} as any), selectGroup: () => {}, selectEntry: async () => {}, getEntrySecret: async () => null, createEntry: async () => ({} as any), deleteEntry: async () => {}, navigate: () => {}, setSearchQuery: () => {} },
    } as any;

    currentAppValue = appValue;
    // @ts-ignore
    const AppCtx = await import('../../context/AppContext');
    // @ts-ignore
    const GroupManager = (await import('../GroupManager')).default;
    render(
      <AppCtx.AppContext.Provider value={appValue}>
        <GroupManager />
      </AppCtx.AppContext.Provider>
    );

    // ensure groups rendered
    await screen.findByText('Work');
    await screen.findByText('Personal');

    // click "+" (New group) icon button to reveal inline input
    const newBtn = screen.getByTitle('New group');
    fireEvent.click(newBtn);

    // type group name in the inline input
    const input = await screen.findByPlaceholderText('New group name...');
    fireEvent.change(input, { target: { value: 'NewGroup' } });

    // click Create
    const createBtn = screen.getByText('Create');
    fireEvent.click(createBtn);

    await waitFor(() => expect(createGroup).toHaveBeenCalledWith('NewGroup'));
  });

  it('renames a group when Save is clicked', async () => {
    const appValue = {
      state: {
        screen: 'groupManager',
        isInitialized: true,
        isUnlocked: true,
        entries: [],
        groups,
        selectedGroupId: null,
        selectedEntry: null,
        searchQuery: '',
        isLoading: false,
        error: null,
      },
      dispatch: () => {},
      actions: { loadGroups, createGroup, updateGroup, deleteGroup, initialize: async () => {}, unlock: async () => true, lock: () => {}, loadEntries: async () => {}, updateEntry: async () => ({} as any), selectGroup: () => {}, selectEntry: async () => {}, getEntrySecret: async () => null, createEntry: async () => ({} as any), deleteEntry: async () => {}, navigate: () => {}, setSearchQuery: () => {} },
    } as any;

    currentAppValue = appValue;
    // eslint-disable-next-line no-undef
    // @ts-ignore
    const AppCtx2 = await import('../../context/AppContext');
    // eslint-disable-next-line no-undef
    // @ts-ignore
    const GroupManager2 = (await import('../GroupManager')).default;
    const { getAllByText } = render(
      <AppCtx2.AppContext.Provider value={appValue}>
        <GroupManager2 />
      </AppCtx2.AppContext.Provider>
    );

    // click first Rename (icon button with title)
    const renameButtons = await screen.findAllByTitle('Rename');
    fireEvent.click(renameButtons[0]);

    // input should appear with current name
    const input = await screen.findByDisplayValue('Work') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'WorkRenamed' } });

    const saveBtn = await screen.findByText('Save');
    fireEvent.click(saveBtn);

    await waitFor(() => expect(updateGroup).toHaveBeenCalledWith('g1', 'WorkRenamed'));
  });

  it('deletes a group when confirmed', async () => {
    const appValue2 = {
      state: {
        screen: 'groupManager',
        isInitialized: true,
        isUnlocked: true,
        entries: [],
        groups,
        selectedGroupId: null,
        selectedEntry: null,
        searchQuery: '',
        isLoading: false,
        error: null,
      },
      dispatch: () => {},
      actions: { loadGroups, createGroup, updateGroup, deleteGroup, initialize: async () => {}, unlock: async () => true, lock: () => {}, loadEntries: async () => {}, updateEntry: async () => ({} as any), selectGroup: () => {}, selectEntry: async () => {}, getEntrySecret: async () => null, createEntry: async () => ({} as any), deleteEntry: async () => {}, navigate: () => {}, setSearchQuery: () => {} },
    } as any;

    currentAppValue = appValue2;
    // @ts-ignore
    const AppCtx3 = await import('../../context/AppContext');
    // @ts-ignore
    const GroupManager3 = (await import('../GroupManager')).default;
    render(
      <AppCtx3.AppContext.Provider value={appValue2}>
        <GroupManager3 />
      </AppCtx3.AppContext.Provider>
    );
    const deleteButtons = await screen.findAllByTitle('Delete');
    fireEvent.click(deleteButtons[1]);

    // Modal appears — confirm delete
    await screen.findByText(/Delete group/);
    // The modal's Delete button (text, not icon)
    const modalDeleteBtn = screen.getAllByText('Delete').pop()!;
    fireEvent.click(modalDeleteBtn);

    await waitFor(() => expect(deleteGroup).toHaveBeenCalledWith('g2'));
  });
});
