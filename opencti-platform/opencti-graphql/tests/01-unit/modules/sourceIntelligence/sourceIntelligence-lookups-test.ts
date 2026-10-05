import { describe, expect, it, vi } from 'vitest';

const requested: string[][] = [];

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  internalFindByIds: vi.fn(async (_context: unknown, _user: unknown, ids: string[]) => {
    requested.push(ids);
    return ids.map((id) => ({ internal_id: id, created_at: '2026-10-01T00:00:00.000Z', creator_id: ['user-1'] }));
  }),
}));

const { loadStoredDocuments } = await import('../../../../src/manager/sourceIntelligenceManager');

describe('Source intelligence live lookups', () => {
  it('should load every signal object in bounded lookups, duplicates once', async () => {
    const ids = Array.from({ length: 12001 }, (_, i) => `object-${i}`);
    const documents = await loadStoredDocuments({} as any, [...ids, 'object-0']);
    expect(documents.size).toBe(12001);
    expect(requested.map((chunk) => chunk.length)).toEqual([5000, 5000, 2001]);
    expect(documents.get('object-12000')?.creator_id).toEqual(['user-1']);
  });
});
