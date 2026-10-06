import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ACCOUNT_STATUS_EXPIRED } from '../../../../src/config/conf';
import type { UserMergeHandlerContext, UserMergeHandlerPlan } from '../../../../src/modules/userMerge/userMerge-handler';

interface StoredSource {
  account_status?: string;
  merged_into?: string;
  password_history?: string[];
}

let stored: StoredSource | undefined;
const edits: { userId: string; inputs: { key: string; value: string[] }[]; opts?: Record<string, unknown> }[] = [];
const patches: { id: string; patch: Record<string, unknown>; opts?: Record<string, unknown> }[] = [];

vi.mock('../../../../src/database/middleware-loader', () => ({
  storeLoadById: async () => stored,
}));

vi.mock('../../../../src/database/middleware', () => ({
  patchAttribute: async (_context: unknown, _user: unknown, id: string, _type: string, patch: Record<string, unknown>, opts?: Record<string, unknown>) => {
    patches.push({ id, patch, opts });
  },
}));

vi.mock('../../../../src/modules/user/user-domain', () => ({
  userEditField: async (_context: unknown, _user: unknown, userId: string, inputs: { key: string; value: string[] }[], opts?: Record<string, unknown>) => {
    edits.push({ userId, inputs, opts });
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
    patches.length = 0;
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
      opts: { skipUserIndividualSync: true },
    }]);
  });

  it('should empty the password history of the source when it applies', async () => {
    await userMergeSourceDisableHandler.apply(handlerContext, await compute());
    expect(patches).toEqual([{ id: 'source-id', patch: { password_history: [] }, opts: { skipUserIndividualSync: true } }]);
  });

  it('should write nothing when the plan holds no change', async () => {
    stored = { account_status: ACCOUNT_STATUS_EXPIRED, merged_into: 'target-id' };
    expect(await userMergeSourceDisableHandler.apply(handlerContext, await compute())).toEqual(0);
    expect(edits).toEqual([]);
    expect(patches).toEqual([]);
  });

  // The history is emptied after the disable, in a second write: a run stopped in between must finish it
  it('should still plan the write on a disabled source that keeps a password history', async () => {
    stored = { account_status: ACCOUNT_STATUS_EXPIRED, merged_into: 'target-id', password_history: ['$2a$10$hash'] };
    expect(countOf(await compute())).toEqual(1);
  });

  it('should only empty the history of a source already disabled, without disabling it again', async () => {
    stored = { account_status: ACCOUNT_STATUS_EXPIRED, merged_into: 'target-id', password_history: ['$2a$10$hash'] };
    expect(await userMergeSourceDisableHandler.apply(handlerContext, await compute())).toEqual(1);
    expect(edits).toEqual([]);
    expect(patches).toEqual([{ id: 'source-id', patch: { password_history: [] }, opts: { skipUserIndividualSync: true } }]);
  });

  it('should declare the password history it reads', () => {
    expect(userMergeSourceDisableHandler.reads).toContain('User.password_history');
  });

  it('should declare every written field, so the disjointness check sees them', () => {
    expect(userMergeSourceDisableHandler.writes).toContain('User.merged_into');
    expect(userMergeSourceDisableHandler.writes).toContain('User.password_history');
  });
});
