import { afterEach, describe, expect, it, vi } from 'vitest';
import { resetUserMergeHandlers } from '../../../../src/modules/userMerge/userMerge-registry';
import { USER_MERGE_REGISTER_VERSION } from '../../../../src/modules/userMerge/userMerge-register';
import type { UserMergeHandler, UserMergeHandlerPlan } from '../../../../src/modules/userMerge/userMerge-handler';
import { UserMergeRightsStrategy, UserMergeStatus } from '../../../../src/modules/userMerge/userMerge-types';

const openedEntries: { handler: string; dryRun: boolean }[] = [];

vi.mock('../../../../src/modules/userMerge/userMerge-journal', () => ({
  withJournalEntry: async (input: { handler: string; dryRun: boolean }, execute: () => Promise<unknown>) => {
    openedEntries.push({ handler: input.handler, dryRun: input.dryRun });
    return execute();
  },
  readJournalEntries: async () => [],
}));

const { executeUserMerge } = await import('../../../../src/modules/userMerge/userMerge-engine');
const { registerUserMergeHandler } = await import('../../../../src/modules/userMerge/userMerge-registry');

const plan = (handler: string, count: number): UserMergeHandlerPlan => ({
  handler,
  changes: [{ register_row_id: 'user.password', entity_type: 'User', count, exact: true }],
  alerts: [],
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

const execute = (dryRun: boolean) => executeUserMerge(
  {} as never,
  'source-id',
  'target-id',
  { dryRun, rightsStrategy: UserMergeRightsStrategy.Strict },
);

describe('userMerge engine', () => {
  afterEach(() => {
    resetUserMergeHandlers();
    openedEntries.length = 0;
    vi.restoreAllMocks();
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
    expect(apply).not.toHaveBeenCalled();
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

  it('should succeed with an empty report when no handler is registered', async () => {
    const result = await execute(false);
    expect(result.status).toEqual(UserMergeStatus.Success);
    expect(result.report?.handlers).toEqual([]);
    expect(result.report?.register_version).toEqual(USER_MERGE_REGISTER_VERSION);
  });
});
