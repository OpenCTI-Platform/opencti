import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { UserMergeRewriteCandidate } from '../../../../src/modules/userMerge/userMerge-bulk';
import type { UserMergeHandlerContext, UserMergeHandlerPlan } from '../../../../src/modules/userMerge/userMerge-handler';

const SOURCE = '11111111-1111-4111-8111-111111111111';
const TARGET = '22222222-2222-4222-8222-222222222222';

// One page holds what the scan hands over at once; every record names the source in its input.
const recordsOf = (prefix: string, count: number, index = 'opencti_history-000001'): UserMergeRewriteCandidate[] => {
  return Array.from({ length: count }, (_, i) => ({ id: `${prefix}-${i}`, index, source: { context_data: { input: { recipients: [SOURCE] } } } }));
};

let pages: UserMergeRewriteCandidate[][] = [];
let failOnBulk: number | undefined;
const bulks: { count: number; refresh?: boolean }[] = [];
const refreshes: string[][] = [];

// The payload scan hands over these pages; the subject-ids scan of compute finds nothing.
vi.mock('../../../../src/modules/userMerge/userMerge-bulk', () => ({
  userMergeScanPagesForRewrite: async (_context: unknown, _indices: unknown, query: unknown, onPage: (page: UserMergeRewriteCandidate[]) => Promise<void> | void) => {
    if (!JSON.stringify(query).includes('context_data.input')) {
      return;
    }
    for (let i = 0; i < pages.length; i += 1) {
      await onPage(pages[i]);
    }
  },
  userMergeBulkRewrite: async (_context: unknown, _label: string, updates: unknown[], opts: { refresh?: boolean } = {}) => {
    if (failOnBulk === bulks.length) {
      throw new Error('bulk rejected');
    }
    bulks.push({ count: updates.length, refresh: opts.refresh });
    return updates.length;
  },
  userMergeBulkUpdate: async () => ({ updated: 3, total: 3, failures: [], version_conflicts: 0 }),
  userMergeRefresh: async (_label: string, indices: string[]) => {
    refreshes.push(indices);
  },
}));

const { userMergeHistoryPayloadHandler } = await import('../../../../src/modules/userMerge/userMerge-historyPayloadHandler');

const handlerContext = { context: {}, sourceId: SOURCE, targetId: TARGET, mergeStartedAt: new Date() } as unknown as UserMergeHandlerContext;
const plan = { changes: [] } as unknown as UserMergeHandlerPlan;

describe('history payload rewriting at scale', () => {
  beforeEach(() => {
    pages = [];
    failOnBulk = undefined;
    bulks.length = 0;
    refreshes.length = 0;
  });

  // Collected over the whole scan, the rewrites would make the peak memory and the request size
  // grow with the history of the user rather than with a page.
  it('should write one bulk per page, unrefreshed, and refresh the written indices once', async () => {
    pages = [recordsOf('a', 3), recordsOf('b', 2, 'opencti_history-000002')];
    const updated = await userMergeHistoryPayloadHandler.apply(handlerContext, plan);
    expect(bulks).toEqual([{ count: 3, refresh: false }, { count: 2, refresh: false }]);
    expect(refreshes).toEqual([['opencti_history-000001', 'opencti_history-000002']]);
    expect(updated).toEqual(3 + 5);
  });

  it('should count the records of every page without writing anything', async () => {
    pages = [recordsOf('a', 3), recordsOf('b', 2)];
    const computed = await userMergeHistoryPayloadHandler.compute(handlerContext);
    expect(computed.changes[0].count).toEqual(5);
    expect(bulks).toEqual([]);
  });

  // The pages written before the failure stay written: reporting zero would read as "nothing was touched".
  it('should report what was already written when a page fails', async () => {
    pages = [recordsOf('a', 3), recordsOf('b', 2)];
    failOnBulk = 1;
    const failure = await userMergeHistoryPayloadHandler.apply(handlerContext, plan).catch((err) => err);
    expect(failure.extensions.data.updated).toEqual(3 + 3);
    expect(refreshes).toEqual([]);
  });
});
