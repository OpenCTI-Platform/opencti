import { describe, expect, it, vi } from 'vitest';

let journalEntries: unknown[] = [];

vi.mock('../../../../src/database/redis', () => ({
  redisUserMergeJournalRead: async () => journalEntries,
  redisUserMergeJournalUpsert: async () => undefined,
}));

const { resolveMergeStartedAt } = await import('../../../../src/modules/userMerge/userMerge-journal');

const FALLBACK = new Date('2025-06-01T12:00:00.000Z');

const entry = (overrides: Record<string, unknown>) => ({
  source_user_id: 'source-id',
  target_user_id: 'target-id',
  dry_run: false,
  started_at: '2025-01-01T00:00:00.000Z',
  ...overrides,
});

describe('merge start resolution', () => {
  it('should fall back to the given instant when the pair was never merged', async () => {
    journalEntries = [];
    expect(await resolveMergeStartedAt('source-id', 'target-id', FALLBACK)).toEqual(FALLBACK);
  });

  // The boundary has to name the first merge, not the last: the deletion gate answers by running a
  // fresh dry-run, and anchoring on anything later would let the first merge's own traces count as
  // references still pending.
  it('should take the earliest real run on the pair', async () => {
    journalEntries = [
      entry({ started_at: '2025-03-02T00:00:00.000Z' }),
      entry({ started_at: '2025-03-01T08:30:00.000Z' }),
      entry({ started_at: '2025-03-01T09:00:00.000Z' }),
    ];
    expect((await resolveMergeStartedAt('source-id', 'target-id', FALLBACK)).toISOString())
      .toEqual('2025-03-01T08:30:00.000Z');
  });

  it('should ignore dry-runs, which wrote nothing to bound', async () => {
    journalEntries = [
      entry({ dry_run: true, started_at: '2025-02-01T00:00:00.000Z' }),
      entry({ started_at: '2025-03-01T00:00:00.000Z' }),
    ];
    expect((await resolveMergeStartedAt('source-id', 'target-id', FALLBACK)).toISOString())
      .toEqual('2025-03-01T00:00:00.000Z');
  });

  it('should ignore a run on another pair', async () => {
    journalEntries = [
      entry({ source_user_id: 'other-source', started_at: '2025-01-01T00:00:00.000Z' }),
      entry({ target_user_id: 'other-target', started_at: '2025-01-02T00:00:00.000Z' }),
      entry({ started_at: '2025-03-01T00:00:00.000Z' }),
    ];
    expect((await resolveMergeStartedAt('source-id', 'target-id', FALLBACK)).toISOString())
      .toEqual('2025-03-01T00:00:00.000Z');
  });

  it('should fall back rather than return an invalid date', async () => {
    journalEntries = [entry({ started_at: 'not-a-date' })];
    expect(await resolveMergeStartedAt('source-id', 'target-id', FALLBACK)).toEqual(FALLBACK);
  });
});
