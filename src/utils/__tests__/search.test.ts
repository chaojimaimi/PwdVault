import { describe, it, expect } from 'vitest';
import { searchEntries } from '../search';
import type { EntrySummary } from '../../types';

const entries: EntrySummary[] = [
  { id: '1', title: 'GitHub', username: 'dev@github.com', url: 'https://github.com', tags: ['dev'], group_id: null, created_at: 0, updated_at: 0 },
  { id: '2', title: 'Gmail', username: 'user@gmail.com', url: 'https://mail.google.com', tags: ['email'], group_id: null, created_at: 0, updated_at: 0 },
  { id: '3', title: 'AWS Console', username: 'admin@company.com', url: 'https://console.aws.amazon.com', tags: ['cloud', 'work'], group_id: null, created_at: 0, updated_at: 0 },
  { id: '4', title: 'Netflix', username: 'viewer@example.com', url: 'https://netflix.com', tags: ['streaming'], group_id: null, created_at: 0, updated_at: 0 },
];

describe('searchEntries', () => {
  it('returns all entries when query is empty', () => {
    expect(searchEntries(entries, '')).toHaveLength(4);
    expect(searchEntries(entries, '  ')).toHaveLength(4);
  });

  it('finds exact title match', () => {
    const results = searchEntries(entries, 'GitHub');
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('1');
  });

  it('finds fuzzy title match with typo', () => {
    const results = searchEntries(entries, 'githb');
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results.some(r => r.id === '1')).toBe(true);
  });

  it('finds by username', () => {
    const results = searchEntries(entries, 'admin@company');
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('3');
  });

  it('finds by url domain', () => {
    const results = searchEntries(entries, 'netflix');
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results.some(r => r.id === '4')).toBe(true);
  });

  it('finds by tag', () => {
    const results = searchEntries(entries, 'streaming');
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results.some(r => r.id === '4')).toBe(true);
  });

  it('returns empty for no match', () => {
    const results = searchEntries(entries, 'zzzzznonexistent');
    expect(results).toHaveLength(0);
  });
});
