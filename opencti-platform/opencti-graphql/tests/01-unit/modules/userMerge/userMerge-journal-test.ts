import { beforeEach, describe, expect, it, vi } from 'vitest';

let journalEntries: unknown[] = [];

// One-based indices of the upsert calls Redis should reject. An entry costs two calls, opening
// then closing, and the journal is deliberately asymmetrical between the two.
let rejectedUpsertCalls: number[] = [];
let upsertCallCount = 0;
const upserts: Record<string, unknown>[] = [];

vi.mock('../../../../src/database/redis', () => ({
  redisUserMergeJournalRead: async () => journalEntries,
  redisUserMergeJournalUpsert: async (_id: string, _mergeId: string, payload: Record<string, unknown>) => {
    upsertCallCount += 1;
    if (rejectedUpsertCalls.includes(upsertCallCount)) {
      throw new Error('redis is down');
    }
    upserts.push(payload);
  },
}));

const { journalRefusal, resolveMergeStartedAt, withJournalEntry } = await import('../../../../src/modules/userMerge/userMerge-journal');
const { UserMergeStatus } = await import('../../../../src/modules/userMerge/userMerge-types');

const FALLBACK = new Date('2025-06-01T12:00:00.000Z');

const entry = (overrides: Record<string, unknown>) => ({
  source_user_id: 'source-id',
  target_user_id: 'target-id',
  dry_run: false,
  started_at: '2025-01-01T00:00:00.000Z',
  ...overrides,
});

const handlerInput = { mergeId: 'merge-1', sourceId: 'source-id', targetId: 'target-id', handler: 'handler-a', dryRun: false };
const handlerOutcome = { handler: 'handler-a', changes: [], alerts: [], updated: 4 };

describe('journal resilience to a broken redis', () => {
  beforeEach(() => {
    upsertCallCount = 0;
    rejectedUpsertCalls = [];
  });

  // The handler has already written to the platform at this point. Losing the trace is bad;
  // reporting the write as failed, and aborting the merge over it, is worse.
  it('should keep a successful handler successful when the entry cannot be closed', async () => {
    rejectedUpsertCalls = [2];
    await expect(withJournalEntry(handlerInput, async () => handlerOutcome)).resolves.toEqual(handlerOutcome);
  });

  it('should still surface the handler failure when the entry cannot be closed either', async () => {
    rejectedUpsertCalls = [2];
    await expect(withJournalEntry(handlerInput, async () => {
      throw new Error('handler exploded');
    })).rejects.toThrow('handler exploded');
  });

  // Symmetrical to the two above on purpose: failing before anything is written is the safe
  // direction, so opening keeps throwing.
  it('should refuse to run a handler it cannot open an entry for', async () => {
    rejectedUpsertCalls = [1];
    const execute = vi.fn(async () => handlerOutcome);
    await expect(withJournalEntry(handlerInput, execute)).rejects.toThrow('redis is down');
    expect(execute).not.toHaveBeenCalled();
  });
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

const refusalInput = { mergeId: 'merge-1', sourceId: 'source-id', targetId: 'target-id', handler: 'user-runtime-state' };

describe('journal entry of a refusal', () => {
  beforeEach(() => {
    upserts.length = 0;
    upsertCallCount = 0;
    rejectedUpsertCalls = [];
  });

  // The dry pass of a real run is journalled as dry, so a run refused before the write loop leaves
  // the exact entries a plain dry-run leaves. Without this one the two cannot be told apart.
  it('should name the handler that diverged and carry the reason', async () => {
    await journalRefusal(refusalInput, 'Platform state changed between the dry pass and the real pass, nothing was written: real only [user.password|User|2|true]');
    expect(upserts[0]).toMatchObject({ handler: 'user-runtime-state', merge_id: 'merge-1' });
    expect(upserts[1]).toMatchObject({
      status: UserMergeStatus.Failed,
      updated_count: 0,
      message: expect.stringContaining('real only [user.password|User|2|true]'),
    });
  });

  // resolveMergeStartedAt anchors the history cut on the runs that could have written. A refusal
  // recorded as real would move that anchor back to a run that wrote nothing, dropping the history
  // written since out of the scan and letting the deletion gate open on an incomplete merge.
  it('should record the refusal as dry, since it wrote nothing to anchor the history cut on', async () => {
    await journalRefusal(refusalInput, 'nothing was written');
    expect(upserts[0]).toMatchObject({ dry_run: true });
  });

  // The journal is diagnostic: it must not replace the refusal the caller is about to raise with
  // an error about the trace of it.
  it('should not propagate a journal write failure', async () => {
    rejectedUpsertCalls = [1, 2];
    await expect(journalRefusal(refusalInput, 'nothing was written')).resolves.toBeUndefined();
  });
});
