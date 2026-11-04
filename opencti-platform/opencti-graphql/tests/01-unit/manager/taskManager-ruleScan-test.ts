import { beforeEach, describe, expect, it, vi } from 'vitest';
import { taskRule } from '../../../src/manager/taskManager';
import { elList } from '../../../src/database/engine';
import { ADMIN_USER, testContext } from '../../utils/testQuery';

vi.mock('../../../src/database/engine', async (importOriginal) => {
  const actual: object = await importOriginal();
  return { ...actual, elList: vi.fn() };
});

vi.mock('../../../src/domain/rules', async (importOriginal) => {
  const actual: object = await importOriginal();
  return { ...actual, getRule: vi.fn(async () => ({ id: 'rule-test', scan: { types: ['Report'] } })) };
});

const scanWith = async (enable: boolean, taskPosition: string | null | undefined) => {
  vi.mocked(elList).mockClear();
  await taskRule(testContext, ADMIN_USER, { rule: 'rule-test', enable, task_position: taskPosition }, async () => {});
  expect(vi.mocked(elList)).toHaveBeenCalledTimes(1);
  return vi.mocked(elList).mock.calls[0][3] as { orderBy: string; after?: string | null };
};

describe('Rule task scan order', () => {
  beforeEach(() => {
    vi.mocked(elList).mockClear();
  });

  it.each([true, false])('should scan a new task by creation date (enable: %s)', async (enable) => {
    // Applying or clearing the rule updates the scanned elements: an updated_at order would list them again
    for (const taskPosition of [null, undefined, '']) {
      const options = await scanWith(enable, taskPosition);
      expect(options.orderBy).toEqual('created_at');
    }
  });

  it.each([true, false])('should resume a legacy position on the order its cursor was built on (enable: %s)', async (enable) => {
    const legacyPosition = 'WyIyMDI2LTAxLTAxVDAwOjAwOjAwLjAwMFoiLCJyZXBvcnQtLTEiXQ==';
    const options = await scanWith(enable, legacyPosition);
    expect(options.orderBy).toEqual('updated_at');
    expect(options.after).toEqual(legacyPosition);
  });
});
