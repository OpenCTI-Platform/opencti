import { beforeEach, describe, expect, it, vi } from 'vitest';
import { UserMergeStatus } from '../../../../src/modules/userMerge/userMerge-types';

let journalEntries: unknown[] = [];
const upserts: Record<string, unknown>[] = [];

vi.mock('../../../../src/database/redis', () => ({
  redisUserMergeJournalRead: async () => journalEntries,
  redisUserMergeJournalUpsert: async (_id: string, _mergeId: string, payload: Record<string, unknown>) => {
    upserts.push(payload);
  },
}));

const { resolveMergeStartedAt, withJournalEntry } = await import('../../../../src/modules/userMerge/userMerge-journal');

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

const runInput = { mergeId: 'merge-1', sourceId: 'source-id', targetId: 'target-id', handler: 'scalar-user-references', dryRun: false };

const failWith = (data?: Record<string, unknown>) => {
  const err = new Error('User merge bulk update aborted') as Error & { extensions?: unknown };
  if (data) {
    err.extensions = { data };
  }
  return err;
};

const closingEntry = () => upserts[upserts.length - 1];

describe('journal entry of a failed handler', () => {
  beforeEach(() => {
    upserts.length = 0;
  });

  // A bulk rewrite that aborts has already written part of what it selected. Reporting zero reads
  // as "nothing was touched", which is the one conclusion an operator must not draw.
  it('should record how far the handler got before failing', async () => {
    await withJournalEntry(runInput, async () => {
      throw failWith({ updated: 2999, total: 11697 });
    }).catch(() => undefined);
    expect(closingEntry()).toMatchObject({ status: UserMergeStatus.Failed, updated_count: 2999 });
  });

  it('should report zero when the failure says nothing about what it wrote', async () => {
    await withJournalEntry(runInput, async () => {
      throw failWith();
    }).catch(() => undefined);
    expect(closingEntry()).toMatchObject({ status: UserMergeStatus.Failed, updated_count: 0 });
  });

  it('should keep reporting the outcome count on success', async () => {
    await withJournalEntry(runInput, async () => ({ updated: 42 }) as never);
    expect(closingEntry()).toMatchObject({ status: UserMergeStatus.Success, updated_count: 42 });
  });
});
