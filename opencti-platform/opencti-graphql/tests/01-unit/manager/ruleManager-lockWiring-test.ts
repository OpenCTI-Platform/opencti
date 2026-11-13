import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ruleApplyAsync, rulesRescanAsync } from '../../../src/manager/ruleManager';
import { runFunctionAsLongRunning } from '../../../src/database/utils';
import { ADMIN_USER, testContext } from '../../utils/testQuery';

vi.mock('../../../src/database/utils', async (importOriginal) => {
  const actual: object = await importOriginal();
  return { ...actual, runFunctionAsLongRunning: vi.fn(async () => true) };
});

vi.mock('../../../src/domain/rules', async (importOriginal) => {
  const actual: object = await importOriginal();
  return { ...actual, getRule: vi.fn(async (_context: unknown, _user: unknown, id: string) => ({ id })) };
});

vi.mock('../../../src/database/middleware-loader', async (importOriginal) => {
  const actual: object = await importOriginal();
  return { ...actual, internalLoadById: vi.fn(async (_context: unknown, _user: unknown, id: string) => ({ internal_id: id, entity_type: 'Report' })) };
});

// runFunctionAsLongRunning(context, user, functionToRun, executionId, lockId)
const calls = () => vi.mocked(runFunctionAsLongRunning).mock.calls.map((call) => ({ executionId: call[3], lockId: call[4] }));

describe('Rule async calls lock wiring', () => {
  beforeEach(() => {
    vi.mocked(runFunctionAsLongRunning).mockClear();
  });

  it('should make two messages applying the same rule on the same element share the lock, not the execution', async () => {
    await ruleApplyAsync(testContext, ADMIN_USER, 'element-a', 'rule-a', 'message-1');
    await ruleApplyAsync(testContext, ADMIN_USER, 'element-a', 'rule-a', 'message-2');
    await ruleApplyAsync(testContext, ADMIN_USER, 'element-b', 'rule-a', 'message-1');
    const [first, duplicate, otherElement] = calls();
    expect(first.lockId).toBeDefined();
    expect(duplicate.lockId).toEqual(first.lockId);
    expect(duplicate.executionId).not.toEqual(first.executionId);
    expect(otherElement.lockId).not.toEqual(first.lockId);
  });

  it('should make two rescans of the same element share the lock, not the execution', async () => {
    await rulesRescanAsync(testContext, ADMIN_USER, 'element-a', 'message-1');
    await rulesRescanAsync(testContext, ADMIN_USER, 'element-a', 'message-2');
    const [first, duplicate] = calls();
    expect(first.lockId).toBeDefined();
    expect(duplicate.lockId).toEqual(first.lockId);
    expect(duplicate.executionId).not.toEqual(first.executionId);
  });
});
