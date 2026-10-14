import { beforeEach, describe, expect, it, vi } from 'vitest';
import { BYPASS } from '../../../../src/utils/access';
import { UserMergeRightsStrategy, UserMergeStatus } from '../../../../src/modules/userMerge/userMerge-types';
import type { AuthUser } from '../../../../src/types/user';

interface PublishedAction {
  event_scope: string;
  event_access: string;
  message: string;
  context_data?: { id: string };
}

const published: PublishedAction[] = [];
let mergeStatus = UserMergeStatus.Success;
let publishRejects = false;

vi.mock('../../../../src/listener/UserActionListener', () => ({
  publishUserAction: async (action: PublishedAction) => {
    if (publishRejects) {
      throw new Error('activity listener down');
    }
    published.push(action);
  },
}));

const users: Record<string, unknown> = {
  'source-id': { internal_id: 'source-id', user_email: 'source@filigran.io' },
  'target-id': { internal_id: 'target-id', user_email: 'target@filigran.io' },
};

vi.mock('../../../../src/database/middleware-loader', () => ({
  storeLoadById: async (_context: unknown, _user: unknown, id: string) => users[id],
}));

vi.mock('../../../../src/modules/userMerge/userMerge-engine', () => ({
  executeUserMerge: async (_context: unknown, sourceId: string, targetId: string, options: { dryRun: boolean }) => ({
    id: 'merge-id',
    source_id: sourceId,
    target_id: targetId,
    dry_run: options.dryRun,
    rights_strategy: UserMergeRightsStrategy.Strict,
    status: mergeStatus,
    started_at: new Date(),
  }),
  readUserMergeJournal: async () => [],
}));

const { userMerge } = await import('../../../../src/modules/userMerge/userMerge-domain');

const admin = { id: 'admin-id', capabilities: [{ name: BYPASS }] } as AuthUser;

const merge = (dryRun: boolean) => userMerge({} as never, admin, 'source-id', 'target-id', { dryRun });

describe('merge trace', () => {
  beforeEach(() => {
    published.length = 0;
    mergeStatus = UserMergeStatus.Success;
    publishRejects = false;
  });

  it('should emit an administration trace naming both accounts on a successful run', async () => {
    await merge(false);
    expect(published).toHaveLength(1);
    expect(published[0].message).toEqual('merges user `source@filigran.io` into user `target@filigran.io`');
    expect(published[0].event_access).toEqual('administration');
  });

  // The question asked later is why that account is disabled, so the trace is filed on the source.
  it('should file the trace on the source account', async () => {
    await merge(false);
    expect(published[0].context_data?.id).toEqual('source-id');
  });

  it('should not emit a trace for a dry-run, which changed nothing', async () => {
    await merge(true);
    expect(published).toEqual([]);
  });

  it('should not emit a trace when the merge failed', async () => {
    mergeStatus = UserMergeStatus.Failed;
    await merge(false);
    expect(published).toEqual([]);
  });

  it('should refuse an unknown account before reaching the engine', async () => {
    await expect(userMerge({} as never, admin, 'source-id', 'ghost-id', { dryRun: false })).rejects.toThrow('Unknown target user');
    expect(published).toEqual([]);
  });

  // The trace is published once every handler has written. A listener rejecting there would
  // answer an error for an applied merge and drop the id the operator reads the journal with.
  it('should return the merge when the trace could not be published', async () => {
    publishRejects = true;
    const result = await merge(false);
    expect(result.status).toEqual(UserMergeStatus.Success);
    expect(result.id).toEqual('merge-id');
  });
});
