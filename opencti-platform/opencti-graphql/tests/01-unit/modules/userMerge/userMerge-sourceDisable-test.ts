import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ACCOUNT_STATUS_EXPIRED } from '../../../../src/config/conf';
import type { UserMergeHandlerContext, UserMergeHandlerPlan } from '../../../../src/modules/userMerge/userMerge-handler';

interface StoredSource {
  account_status?: string;
  merged_into?: string;
}

let stored: StoredSource | undefined;
const edits: { userId: string; inputs: { key: string; value: string[] }[] }[] = [];

vi.mock('../../../../src/database/middleware-loader', () => ({
  storeLoadById: async () => stored,
}));

vi.mock('../../../../src/domain/user', () => ({
  userEditField: async (_context: unknown, _user: unknown, userId: string, inputs: { key: string; value: string[] }[]) => {
    edits.push({ userId, inputs });
  },
}));

const { userMergeSourceDisableHandler } = await import('../../../../src/modules/userMerge/userMerge-sourceDisableHandler');

const handlerContext = { context: {}, sourceId: 'source-id', targetId: 'target-id' } as unknown as UserMergeHandlerContext;

const compute = () => userMergeSourceDisableHandler.compute(handlerContext);
const countOf = (plan: UserMergeHandlerPlan) => plan.changes[0].count;

describe('source disable handler', () => {
  beforeEach(() => {
    stored = { account_status: 'Active' };
    edits.length = 0;
  });

  it('should plan the disable of an active source', async () => {
    expect(countOf(await compute())).toEqual(1);
  });

  it('should plan nothing on a source already disabled and marked for this target', async () => {
    stored = { account_status: ACCOUNT_STATUS_EXPIRED, merged_into: 'target-id' };
    expect(countOf(await compute())).toEqual(0);
  });

  // An administrator can expire an account before asking for the merge. Reading the status alone
  // would report nothing to do, and the mark that closes the ordinary deletion path would never be
  // written on precisely the account the merge is about to empty.
  it('should still plan the write on a source expired before the merge', async () => {
    stored = { account_status: ACCOUNT_STATUS_EXPIRED };
    expect(countOf(await compute())).toEqual(1);
  });

  it('should still plan the write on a source marked for another target', async () => {
    stored = { account_status: ACCOUNT_STATUS_EXPIRED, merged_into: 'another-target-id' };
    expect(countOf(await compute())).toEqual(1);
  });

  it('should record the merge target on the source when it applies', async () => {
    await userMergeSourceDisableHandler.apply(handlerContext, await compute());
    expect(edits).toEqual([{
      userId: 'source-id',
      inputs: [
        { key: 'account_status', value: [ACCOUNT_STATUS_EXPIRED] },
        { key: 'merged_into', value: ['target-id'] },
      ],
    }]);
  });

  it('should write nothing when the plan holds no change', async () => {
    stored = { account_status: ACCOUNT_STATUS_EXPIRED, merged_into: 'target-id' };
    expect(await userMergeSourceDisableHandler.apply(handlerContext, await compute())).toEqual(0);
    expect(edits).toEqual([]);
  });

  it('should declare both written fields, so the disjointness check sees them', () => {
    expect(userMergeSourceDisableHandler.writes).toContain('User.merged_into');
  });
});
