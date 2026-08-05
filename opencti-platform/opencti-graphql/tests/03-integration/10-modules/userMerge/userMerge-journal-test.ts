import { describe, expect, it } from 'vitest';
import { closeJournalEntry, openJournalEntry, readJournalEntries, withJournalEntry } from '../../../../src/modules/userMerge/userMerge-journal';
import { UserMergeStatus } from '../../../../src/modules/userMerge/userMerge-types';

const newMergeId = () => `test-merge-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

describe('userMerge journal', () => {
  it('should make an entry readable straight away, while the handler is still running', async () => {
    const mergeId = newMergeId();
    await openJournalEntry({
      mergeId,
      sourceId: 'source-id',
      targetId: 'target-id',
      handler: 'test-handler',
      dryRun: false,
    });
    // No wait: unlike an indexed write, the entry is visible as soon as it is written, which
    // is what makes the follow-up query usable during a run.
    const entries = await readJournalEntries(mergeId);
    expect(entries.length).toEqual(1);
    expect(entries[0].status).toEqual(UserMergeStatus.Running);
    expect(entries[0].completed_at).toBeUndefined();
  });

  it('should record the outcome when the entry is closed', async () => {
    const mergeId = newMergeId();
    const entryId = await openJournalEntry({
      mergeId,
      sourceId: 'source-id',
      targetId: 'target-id',
      handler: 'test-handler',
      dryRun: false,
    });
    await closeJournalEntry(entryId, mergeId, {
      status: UserMergeStatus.Success,
      outcome: { handler: 'test-handler', changes: [], alerts: [], updated: 42 },
    });
    const entries = await readJournalEntries(mergeId);
    expect(entries.length).toEqual(1);
    expect(entries[0].status).toEqual(UserMergeStatus.Success);
    expect(entries[0].updated_count).toEqual(42);
    expect(entries[0].completed_at).toBeDefined();
    // Closing must not lose what opening recorded.
    expect(entries[0].handler).toEqual('test-handler');
    expect(entries[0].started_at).toBeDefined();
  });

  it('should leave a failed entry when the handler throws', async () => {
    const mergeId = newMergeId();
    const input = { mergeId, sourceId: 'source-id', targetId: 'target-id', handler: 'exploding-handler', dryRun: false };
    await expect(withJournalEntry(input, async () => {
      throw new Error('handler exploded');
    })).rejects.toThrow('handler exploded');
    const entries = await readJournalEntries(mergeId);
    expect(entries.length).toEqual(1);
    expect(entries[0].status).toEqual(UserMergeStatus.Failed);
    expect(entries[0].message).toEqual('handler exploded');
  });

  it('should isolate entries per merge id', async () => {
    const firstMergeId = newMergeId();
    const secondMergeId = newMergeId();
    const base = { sourceId: 'source-id', targetId: 'target-id', handler: 'test-handler', dryRun: true };
    await openJournalEntry({ ...base, mergeId: firstMergeId });
    await openJournalEntry({ ...base, mergeId: secondMergeId });
    const firstEntries = await readJournalEntries(firstMergeId);
    expect(firstEntries.length).toEqual(1);
    expect(firstEntries[0].merge_id).toEqual(firstMergeId);
  });

  it('should be readable without a merge id, across runs', async () => {
    const mergeId = newMergeId();
    const base = { sourceId: 'source-id', targetId: 'target-id', handler: 'test-handler', dryRun: true };
    await openJournalEntry({ ...base, mergeId });
    const all = await readJournalEntries();
    expect(all.some((entry) => entry.merge_id === mergeId)).toBe(true);
  });

  it('should cap the returned entries when a page size is given', async () => {
    const mergeId = newMergeId();
    const base = { sourceId: 'source-id', targetId: 'target-id', dryRun: true, mergeId };
    await openJournalEntry({ ...base, handler: 'handler-a' });
    await openJournalEntry({ ...base, handler: 'handler-b' });
    expect((await readJournalEntries(mergeId)).length).toEqual(2);
    expect((await readJournalEntries(mergeId, 1)).length).toEqual(1);
  });
});
