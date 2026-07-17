import { test, expect } from 'vitest';

const mockGroups = [
  { id: 'g1', name: 'Work', created_at: 1, updated_at: 1 },
  { id: 'g2', name: 'Personal', created_at: 1, updated_at: 1 },
];

const mockEntries = [
  { id: 'e1', title: 'A', url: '', username: 'u1', tags: [], created_at: 0, updated_at: 0, group_id: 'g1' },
  { id: 'e2', title: 'B', url: '', username: 'u2', tags: [], created_at: 0, updated_at: 0, group_id: 'g2' },
  { id: 'e3', title: 'C', url: '', username: 'u3', tags: [], created_at: 0, updated_at: 0, group_id: null },
];

test('filters entries by selected group (pure function)', () => {
  const filterEntries = (entries: any[], selectedGroup: string | null) =>
    entries.filter((entry) => {
      if (selectedGroup) return entry.group_id === selectedGroup;
      return true;
    });

  const all = filterEntries(mockEntries, null).map((e) => e.title);
  expect(all).toEqual(['A', 'B', 'C']);

  const g1 = filterEntries(mockEntries, 'g1').map((e) => e.title);
  expect(g1).toEqual(['A']);

  const g2 = filterEntries(mockEntries, 'g2').map((e) => e.title);
  expect(g2).toEqual(['B']);
});
