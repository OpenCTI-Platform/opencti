import { beforeEach, describe, expect, it, vi } from 'vitest';
import { logApp } from '../../../src/config/conf';
import { dataSanityListHandler } from '../../../src/manager/dataSanityManager';
import { getOperationSkipReason, markOperationAsExecuted, markOperationAsRunning } from '../../../src/modules/dataSanity/dataSanity-domain';
import { sanityOperationList } from '../../../src/modules/dataSanity/dataSanity-operations';

vi.mock('../../../src/modules/dataSanity/dataSanity-domain', () => ({
  findForceRunOperations: vi.fn().mockResolvedValue([]),
  getOperationSkipReason: vi.fn(),
  getRunningLockSkipReason: vi.fn(),
  markOperationAsExecuted: vi.fn(),
  markOperationAsRunning: vi.fn(),
}));

vi.mock('../../../src/modules/dataSanity/dataSanity-operations', () => ({
  sanityOperationList: vi.fn(),
}));

const operationRun = vi.fn();
const operation = { identifier: 'mockOperation', execution_type: 'recurring', operationRun, dryRun: vi.fn() };

/**
 * Two different failures used to share one catch here: the operation failing, and the write that
 * records its outcome failing. Only the second is actionable — the operation's own failure is
 * persisted and surfaced in the UI, while a failed result write leaves the operation flagged as
 * running, so every later pass skips it over the running lock. The recovery write was also
 * `.catch(() => {})`, which swallowed exactly that.
 */
describe('Data sanity manager failure severity', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (sanityOperationList as any).mockReturnValue([operation]);
    (getOperationSkipReason as any).mockResolvedValue(undefined);
    (markOperationAsRunning as any).mockResolvedValue(undefined);
    (markOperationAsExecuted as any).mockResolvedValue(undefined);
  });

  it('should report a failing operation as a warning and still record the outcome', async () => {
    const logAppErrorSpy = vi.spyOn(logApp, 'error');
    const logAppWarnSpy = vi.spyOn(logApp, 'warn');
    operationRun.mockRejectedValue(new Error('operation blew up'));

    await dataSanityListHandler({} as any, {} as any);

    expect(logAppWarnSpy).toHaveBeenCalledTimes(1);
    expect(logAppWarnSpy.mock.calls[0][0]).toContain('Data sanity operation failed');
    expect(logAppErrorSpy, 'A reported operation failure is not an application error.').not.toHaveBeenCalled();
    // The outcome still reaches the database, which is why warn is enough.
    const executedCall = (markOperationAsExecuted as any).mock.calls[0];
    expect(executedCall[4], 'success flag').toBe(false);
    expect(executedCall[5], 'run message').toBe('operation blew up');
  });

  it('should report a failure to record the result as an error', async () => {
    const logAppErrorSpy = vi.spyOn(logApp, 'error');
    const logAppWarnSpy = vi.spyOn(logApp, 'warn');
    operationRun.mockResolvedValue({ some: 'output' });
    (markOperationAsExecuted as any).mockRejectedValue(new Error('elastic is down'));

    await dataSanityListHandler({} as any, {} as any);

    expect(logAppErrorSpy).toHaveBeenCalledTimes(1);
    expect(logAppErrorSpy.mock.calls[0][0]).toContain('result could not be recorded');
    expect(logAppWarnSpy, 'The operation itself succeeded.').not.toHaveBeenCalled();
  });

  it('should report an error when the result of a failed operation cannot be recorded either', async () => {
    const logAppErrorSpy = vi.spyOn(logApp, 'error');
    const logAppWarnSpy = vi.spyOn(logApp, 'warn');
    operationRun.mockRejectedValue(new Error('operation blew up'));
    (markOperationAsExecuted as any).mockRejectedValue(new Error('elastic is down'));

    await dataSanityListHandler({} as any, {} as any);

    // Both halves are reported, at their own level. The old code silently swallowed the second.
    expect(logAppWarnSpy).toHaveBeenCalledTimes(1);
    expect(logAppErrorSpy).toHaveBeenCalledTimes(1);
    expect(logAppErrorSpy.mock.calls[0][0]).toContain('result could not be recorded');
  });

  it('should log nothing above info when the operation completes and is recorded', async () => {
    const logAppErrorSpy = vi.spyOn(logApp, 'error');
    const logAppWarnSpy = vi.spyOn(logApp, 'warn');
    operationRun.mockResolvedValue({ some: 'output' });

    await dataSanityListHandler({} as any, {} as any);

    expect(markOperationAsExecuted).toHaveBeenCalledTimes(1);
    expect((markOperationAsExecuted as any).mock.calls[0][4], 'success flag').toBe(true);
    expect(logAppErrorSpy).not.toHaveBeenCalled();
    expect(logAppWarnSpy).not.toHaveBeenCalled();
  });
});
