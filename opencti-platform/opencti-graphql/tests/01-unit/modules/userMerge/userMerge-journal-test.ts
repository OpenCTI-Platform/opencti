import { beforeEach, describe, expect, it, vi } from 'vitest';

const upsert = vi.fn();
vi.mock('../../../../src/database/redis', () => ({
  redisUserMergeJournalUpsert: (...args: unknown[]) => upsert(...args),
  redisUserMergeJournalRead: async () => [],
}));

const { journalRefusal, withJournalEntry } = await import('../../../../src/modules/userMerge/userMerge-journal');
const { UserMergeStatus } = await import('../../../../src/modules/userMerge/userMerge-types');

const input = { mergeId: 'merge-1', sourceId: 'source', targetId: 'target', handler: 'handler-a', dryRun: false };
const outcome = { handler: 'handler-a', changes: [], alerts: [], updated: 4 };

describe('userMerge journal', () => {
  beforeEach(() => {
    upsert.mockReset();
    upsert.mockResolvedValue(undefined);
  });

  it('should record the outcome of a handler that succeeded', async () => {
    await expect(withJournalEntry(input, async () => outcome)).resolves.toEqual(outcome);
    expect(upsert).toHaveBeenCalledTimes(2);
    expect(upsert.mock.calls[1][2]).toMatchObject({ status: UserMergeStatus.Success, updated_count: 4 });
  });

  it('should record a handler that threw, and let the failure through', async () => {
    await expect(withJournalEntry(input, async () => {
      throw new Error('handler exploded');
    })).rejects.toThrow('handler exploded');
    expect(upsert.mock.calls[1][2]).toMatchObject({ status: UserMergeStatus.Failed, message: 'handler exploded' });
  });

  it('should keep a successful handler successful when the journal cannot be written', async () => {
    // The handler has already written to the platform at this point. Losing the trace is bad;
    // reporting the write as failed, and aborting the merge over it, is worse.
    upsert.mockResolvedValueOnce(undefined).mockRejectedValueOnce(new Error('redis is down'));
    await expect(withJournalEntry(input, async () => outcome)).resolves.toEqual(outcome);
  });

  it('should still surface the handler failure when the journal cannot be written either', async () => {
    upsert.mockResolvedValueOnce(undefined).mockRejectedValueOnce(new Error('redis is down'));
    await expect(withJournalEntry(input, async () => {
      throw new Error('handler exploded');
    })).rejects.toThrow('handler exploded');
  });

  it('should refuse to run a handler it cannot open an entry for', async () => {
    // Symmetrical to the above on purpose: failing before anything is written is the safe
    // direction, so opening keeps throwing.
    upsert.mockRejectedValueOnce(new Error('redis is down'));
    const execute = vi.fn(async () => outcome);
    await expect(withJournalEntry(input, execute)).rejects.toThrow('redis is down');
    expect(execute).not.toHaveBeenCalled();
  });
});

const refusalInput = { mergeId: 'merge-1', sourceId: 'source', targetId: 'target', handler: 'user-runtime-state' };

describe('journal entry of a refusal', () => {
  beforeEach(() => {
    upsert.mockReset();
    upsert.mockResolvedValue(undefined);
  });

  // The dry pass of a real run is journalled as dry, so a run refused before the write loop leaves
  // the exact entries a plain dry-run leaves. Without this one the two cannot be told apart.
  it('should name the handler that diverged and carry the reason', async () => {
    await journalRefusal(refusalInput, 'Platform state changed between the dry pass and the real pass, nothing was written: real only [user.password|User|2|true]');
    expect(upsert.mock.calls[0][2]).toMatchObject({ handler: 'user-runtime-state', merge_id: 'merge-1' });
    expect(upsert.mock.calls[1][2]).toMatchObject({
      status: UserMergeStatus.Failed,
      updated_count: 0,
      message: expect.stringContaining('real only [user.password|User|2|true]'),
    });
  });

  // A refusal wrote nothing, and the history cut is anchored on the runs that could have written.
  // Recorded as real it would move that anchor back to a run that wrote nothing, dropping later
  // history out of the scan and letting the deletion gate open on an incomplete merge.
  it('should record the refusal as dry, since it wrote nothing to anchor the history cut on', async () => {
    await journalRefusal(refusalInput, 'nothing was written');
    expect(upsert.mock.calls[0][2]).toMatchObject({ dry_run: true });
  });

  // The journal is diagnostic: it must not replace the refusal the caller is about to raise with
  // an error about the trace of it.
  it('should not propagate a journal write failure', async () => {
    upsert.mockRejectedValue(new Error('redis is down'));
    await expect(journalRefusal(refusalInput, 'nothing was written')).resolves.toBeUndefined();
  });
});
