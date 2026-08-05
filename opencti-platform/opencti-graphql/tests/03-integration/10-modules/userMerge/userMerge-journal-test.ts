import { describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { closeJournalEntry, openJournalEntry, readJournalEntries, withJournalEntry } from '../../../../src/modules/userMerge/userMerge-journal';
import { ENTITY_TYPE_USER_MERGE_JOURNAL } from '../../../../src/modules/userMerge/userMergeJournal-types';
import { UserMergeStatus } from '../../../../src/modules/userMerge/userMerge-types';
import { deleteElementById } from '../../../../src/database/middleware';
import { wait } from '../../../../src/database/utils';

const newMergeId = () => `test-merge-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

const cleanup = async (mergeId: string) => {
  const entries = await readJournalEntries(testContext, ADMIN_USER, mergeId);
  for (let i = 0; i < entries.length; i += 1) {
    await deleteElementById(testContext, ADMIN_USER, entries[i].internal_id, ENTITY_TYPE_USER_MERGE_JOURNAL);
  }
};

describe('userMerge journal', () => {
  it('should make an entry readable while the handler is still running', async () => {
    const mergeId = newMergeId();
    await openJournalEntry(testContext, ADMIN_USER, {
      mergeId,
      sourceId: 'source-id',
      targetId: 'target-id',
      handler: 'test-handler',
      dryRun: false,
    });
    await wait(2000);
    const entries = await readJournalEntries(testContext, ADMIN_USER, mergeId);
    expect(entries.length).toEqual(1);
    expect(entries[0].status).toEqual(UserMergeStatus.Running);
    expect(entries[0].completed_at).toBeUndefined();
    await cleanup(mergeId);
  });

  it('should record the outcome when the entry is closed', async () => {
    const mergeId = newMergeId();
    const entryId = await openJournalEntry(testContext, ADMIN_USER, {
      mergeId,
      sourceId: 'source-id',
      targetId: 'target-id',
      handler: 'test-handler',
      dryRun: false,
    });
    await closeJournalEntry(testContext, ADMIN_USER, entryId, {
      status: UserMergeStatus.Success,
      outcome: { handler: 'test-handler', changes: [], alerts: [], updated: 42 },
    });
    await wait(2000);
    const entries = await readJournalEntries(testContext, ADMIN_USER, mergeId);
    expect(entries.length).toEqual(1);
    expect(entries[0].status).toEqual(UserMergeStatus.Success);
    expect(entries[0].updated_count).toEqual(42);
    expect(entries[0].completed_at).toBeDefined();
    await cleanup(mergeId);
  });

  it('should leave a failed entry when the handler throws', async () => {
    const mergeId = newMergeId();
    const input = { mergeId, sourceId: 'source-id', targetId: 'target-id', handler: 'exploding-handler', dryRun: false };
    await expect(withJournalEntry(testContext, ADMIN_USER, input, async () => {
      throw new Error('handler exploded');
    })).rejects.toThrow('handler exploded');
    await wait(2000);
    const entries = await readJournalEntries(testContext, ADMIN_USER, mergeId);
    expect(entries.length).toEqual(1);
    expect(entries[0].status).toEqual(UserMergeStatus.Failed);
    expect(entries[0].message).toEqual('handler exploded');
    await cleanup(mergeId);
  });

  it('should isolate entries per merge id', async () => {
    const firstMergeId = newMergeId();
    const secondMergeId = newMergeId();
    const base = { sourceId: 'source-id', targetId: 'target-id', handler: 'test-handler', dryRun: true };
    await openJournalEntry(testContext, ADMIN_USER, { ...base, mergeId: firstMergeId });
    await openJournalEntry(testContext, ADMIN_USER, { ...base, mergeId: secondMergeId });
    await wait(2000);
    const firstEntries = await readJournalEntries(testContext, ADMIN_USER, firstMergeId);
    expect(firstEntries.length).toEqual(1);
    expect(firstEntries[0].merge_id).toEqual(firstMergeId);
    await cleanup(firstMergeId);
    await cleanup(secondMergeId);
  });
});
