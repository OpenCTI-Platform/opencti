import { afterEach, describe, expect, it, vi } from 'vitest';
import { resetUserMergeHandlers } from '../../../../src/modules/userMerge/userMerge-registry';
import type { UserMergeHandler, UserMergeHandlerPlan } from '../../../../src/modules/userMerge/userMerge-handler';
import { UserMergeRightsStrategy, UserMergeStatus } from '../../../../src/modules/userMerge/userMerge-types';

const openedEntries: { handler: string; dryRun: boolean }[] = [];
const refusals: { handler: string; message: string }[] = [];
const FIRST_MERGE_STARTED_AT = new Date('2025-03-01T08:30:00.000Z');

vi.mock('../../../../src/modules/userMerge/userMerge-journal', () => ({
  withJournalEntry: async (input: { handler: string; dryRun: boolean }, execute: () => Promise<unknown>) => {
    openedEntries.push({ handler: input.handler, dryRun: input.dryRun });
    return execute();
  },
  journalRefusal: async (input: { handler: string }, message: string) => {
    refusals.push({ handler: input.handler, message });
  },
  readJournalEntries: async () => [],
  resolveMergeStartedAt: async () => FIRST_MERGE_STARTED_AT,
}));

const cacheResets: string[] = [];

vi.mock('../../../../src/database/redis', () => ({
  publishCacheResetEvent: async (entityType: string) => {
    cacheResets.push(entityType);
  },
}));

const storedUsers = new Map<string, unknown>([
  ['source-id', { internal_id: 'source-id', allowed_marking: [], organizations: [], capabilities: [] }],
  ['target-id', { internal_id: 'target-id', allowed_marking: [], organizations: [], capabilities: [] }],
]);

vi.mock('../../../../src/modules/user/user-domain', () => ({
  resolveUserById: async (_context: unknown, id: string) => storedUsers.get(id),
}));

const { executeUserMerge, USER_MERGE_CACHED_ENTITY_TYPES } = await import('../../../../src/modules/userMerge/userMerge-engine');
const { registerUserMergeHandler } = await import('../../../../src/modules/userMerge/userMerge-registry');

const plan = (handler: string, count: number): UserMergeHandlerPlan => ({
  handler,
  changes: [{ register_row_id: 'user.password', entity_type: 'User', count, exact: true }],
  alerts: [],
});

const blockingPlan = (handler: string): UserMergeHandlerPlan => ({
  handler,
  changes: [{ register_row_id: 'user.password', entity_type: 'User', count: 1, exact: true }],
  alerts: [{ register_row_id: 'user.password', kind: 'exposure', message: 'exposure widens', blocking: true }],
});

const mockHandler = (identifier: string, overrides: Partial<UserMergeHandler> = {}): UserMergeHandler => ({
  identifier,
  covers: ['user.password'],
  reads: [`${identifier}.read`],
  writes: [`${identifier}.write`],
  compute: async () => plan(identifier, 3),
  apply: async () => 3,
  ...overrides,
});

const execute = (dryRun: boolean, acknowledgeExposureChange = false) => executeUserMerge(
  {} as never,
  'source-id',
  'target-id',
  { dryRun, rightsStrategy: UserMergeRightsStrategy.Strict, acknowledgeExposureChange },
);

describe('userMerge engine', () => {
  afterEach(() => {
    resetUserMergeHandlers();
    openedEntries.length = 0;
    refusals.length = 0;
    cacheResets.length = 0;
    vi.restoreAllMocks();
  });

  // Handlers write straight to Elasticsearch, which notifies no cache: without the reset a live
  // stream or a trigger keeps evaluating the source id until a restart, on every node.
  it('should reset every cached entity type once the real pass has written', async () => {
    registerUserMergeHandler(mockHandler('handler-a'));
    expect((await execute(false)).status).toEqual(UserMergeStatus.Success);
    expect(cacheResets.sort()).toEqual([...USER_MERGE_CACHED_ENTITY_TYPES].sort());
  });

  it('should reset no cache when nothing was written', async () => {
    let computeCount = 0;
    registerUserMergeHandler(mockHandler('handler-a', {
      compute: async () => {
        computeCount += 1;
        return plan('handler-a', computeCount);
      },
    }));
    await execute(true);
    expect((await execute(false)).status).toEqual(UserMergeStatus.Failed);
    expect(cacheResets).toEqual([]);
  });

  it('should still reset the caches when a handler fails after another one wrote', async () => {
    registerUserMergeHandler(mockHandler('handler-a'));
    registerUserMergeHandler(mockHandler('handler-b', {
      apply: async () => {
        throw new Error('bulk rewrite failed');
      },
    }));
    expect((await execute(false)).status).toEqual(UserMergeStatus.Failed);
    expect(cacheResets.sort()).toEqual([...USER_MERGE_CACHED_ENTITY_TYPES].sort());
  });

  it('should not apply anything in dry mode', async () => {
    const apply = vi.fn(async () => 3);
    registerUserMergeHandler(mockHandler('handler-a', { apply }));
    const result = await execute(true);
    expect(result.status).toEqual(UserMergeStatus.Success);
    expect(apply).not.toHaveBeenCalled();
    expect(result.report?.total_updated).toEqual(0);
    expect(result.report?.handlers.length).toEqual(1);
  });

  it('should report the same changes in both modes', async () => {
    registerUserMergeHandler(mockHandler('handler-a'));
    const dry = await execute(true);
    resetUserMergeHandlers();
    registerUserMergeHandler(mockHandler('handler-a'));
    const real = await execute(false);
    expect(real.report?.handlers[0].changes).toEqual(dry.report?.handlers[0].changes);
    expect(real.report?.total_updated).toEqual(3);
  });

  it('should complete every computation before the first write', async () => {
    const calls: string[] = [];
    registerUserMergeHandler(mockHandler('handler-a', {
      compute: async () => {
        calls.push('compute-a');
        return plan('handler-a', 1);
      },
      apply: async () => {
        calls.push('apply-a');
        return 1;
      },
    }));
    registerUserMergeHandler(mockHandler('handler-b', {
      covers: ['user.otp'],
      compute: async () => {
        calls.push('compute-b');
        return plan('handler-b', 1);
      },
      apply: async () => {
        calls.push('apply-b');
        return 1;
      },
    }));
    await execute(false);
    expect(calls.indexOf('apply-a')).toBeGreaterThan(calls.indexOf('compute-b'));
  });

  it('should refuse to write when the platform state moved between the two passes', async () => {
    let computeCount = 0;
    const apply = vi.fn(async () => 3);
    registerUserMergeHandler(mockHandler('handler-a', {
      compute: async () => {
        computeCount += 1;
        return plan('handler-a', computeCount);
      },
      apply,
    }));
    const result = await execute(false);
    expect(result.status).toEqual(UserMergeStatus.Failed);
    expect(result.message).toContain('Platform state changed');
    expect(result.message).toContain('dry only [user.password|User|1|true]');
    expect(result.message).toContain('real only [user.password|User|2|true]');
    expect(apply).not.toHaveBeenCalled();
  });

  it('should journal the refusal, which a run stopped before the write loop otherwise leaves unrecorded', async () => {
    let computeCount = 0;
    registerUserMergeHandler(mockHandler('handler-a'));
    registerUserMergeHandler(mockHandler('handler-b', {
      compute: async () => {
        computeCount += 1;
        return plan('handler-b', computeCount);
      },
    }));
    await execute(false);
    expect(refusals).toHaveLength(1);
    expect(refusals[0].handler).toEqual('handler-b');
    expect(refusals[0].message).toContain('real only [user.password|User|2|true]');
  });

  it('should leave the platform untouched when a later handler is the one that moved', async () => {
    const apply = vi.fn(async () => 3);
    registerUserMergeHandler(mockHandler('handler-a', { apply }));
    let computeCount = 0;
    registerUserMergeHandler(mockHandler('handler-b', {
      covers: ['user.otp'],
      compute: async () => {
        computeCount += 1;
        return plan('handler-b', computeCount);
      },
    }));
    const result = await execute(false);
    expect(result.status).toEqual(UserMergeStatus.Failed);
    // A refusal that leaves the earlier handlers applied is not recoverable: the platform is
    // half merged and no report describes that state.
    expect(apply).not.toHaveBeenCalled();
  });

  it('should not read a handler destroying what a later one counts as the platform moving', async () => {
    // What the source deactivation does to the sessions the runtime handler counts: a correct
    // merge, not a platform that moved while the operator was reading the report.
    let sessions = 1;
    registerUserMergeHandler(mockHandler('handler-a', {
      apply: async () => {
        sessions = 0;
        return 1;
      },
    }));
    registerUserMergeHandler(mockHandler('handler-b', {
      covers: ['user.otp'],
      compute: async () => plan('handler-b', sessions),
    }));
    const result = await execute(false);
    expect(result.status).toEqual(UserMergeStatus.Success);
    expect(result.report?.handlers[1].changes[0].count).toEqual(1);
  });

  it('should journal both passes and mark them apart', async () => {
    registerUserMergeHandler(mockHandler('handler-a'));
    await execute(false);
    expect(openedEntries).toEqual([
      { handler: 'handler-a', dryRun: true },
      { handler: 'handler-a', dryRun: false },
    ]);
  });

  it('should return a failed result carrying the merge id when a handler throws', async () => {
    registerUserMergeHandler(mockHandler('handler-a', {
      compute: async () => {
        throw new Error('elasticsearch is down');
      },
    }));
    const result = await execute(false);
    expect(result.status).toEqual(UserMergeStatus.Failed);
    expect(result.id).toBeDefined();
    expect(result.message).toEqual('elasticsearch is down');
  });

  it('should fail rather than run without the resolved rights of both users', async () => {
    registerUserMergeHandler(mockHandler('handler-a'));
    const result = await executeUserMerge(
      {} as never,
      'source-id',
      'unknown-id',
      { dryRun: false, rightsStrategy: UserMergeRightsStrategy.Strict, acknowledgeExposureChange: false },
    );
    expect(result.status).toEqual(UserMergeStatus.Failed);
    expect(result.message).toEqual('Cannot resolve the rights of the users to merge');
  });

  it('should succeed with an empty report when no handler is registered', async () => {
    const result = await execute(false);
    expect(result.status).toEqual(UserMergeStatus.Success);
    expect(result.report?.handlers).toEqual([]);
  });

  it('should report a blocking alert in dry mode instead of failing', async () => {
    registerUserMergeHandler(mockHandler('handler-a', { compute: async () => blockingPlan('handler-a') }));
    const result = await execute(true);
    expect(result.status).toEqual(UserMergeStatus.Success);
    expect(result.report?.handlers[0].alerts[0].blocking).toEqual(true);
  });

  it('should refuse to write when a blocking alert is not acknowledged', async () => {
    const apply = vi.fn(async () => 3);
    registerUserMergeHandler(mockHandler('handler-a', { compute: async () => blockingPlan('handler-a'), apply }));
    const result = await execute(false);
    expect(result.status).toEqual(UserMergeStatus.Failed);
    expect(result.message).toContain('unacknowledged');
    expect(apply).not.toHaveBeenCalled();
  });

  it('should write when the blocking alert is acknowledged', async () => {
    const apply = vi.fn(async () => 3);
    registerUserMergeHandler(mockHandler('handler-a', { compute: async () => blockingPlan('handler-a'), apply }));
    const result = await execute(false, true);
    expect(result.status).toEqual(UserMergeStatus.Success);
    expect(apply).toHaveBeenCalled();
  });
});
