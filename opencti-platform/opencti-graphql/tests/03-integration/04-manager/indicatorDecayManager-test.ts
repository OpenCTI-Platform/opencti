import { afterAll, describe, it, vi, expect } from 'vitest';
import { indicatorDecayHandler } from '../../../src/manager/indicatorDecayManager';
import * as indicatorDomain from '../../../src/modules/indicator/indicator-domain';
import type { BasicStoreEntityIndicator } from '../../../src/modules/indicator/indicator-types';
import { logApp } from '../../../src/config/conf';

const indicatorList: BasicStoreEntityIndicator[] = [];
const getMockIndicator = () => {
  const indicator: Partial<BasicStoreEntityIndicator> = {
    id: 'mock-test-indicator',
  };
  return indicator as BasicStoreEntityIndicator;
};
indicatorList.push(getMockIndicator());
// Spied, not mocked: the test setup registers the module descriptors, the indicator one with this manager, so the
// manager and the domain it imports are already evaluated in the worker every test file shares
const findIndicatorsForDecaySpy = vi.spyOn(indicatorDomain, 'findIndicatorsForDecay').mockResolvedValue(indicatorList);
const updateIndicatorDecayScoreSpy = vi.spyOn(indicatorDomain, 'updateIndicatorDecayScore')
  .mockImplementationOnce(async () => null)
  .mockImplementationOnce(async () => {
    throw new Error('Second time test is throwing error');
  });

describe('Testing indicatorDecayManager', () => {
  afterAll(() => {
    findIndicatorsForDecaySpy.mockRestore();
    updateIndicatorDecayScoreSpy.mockRestore();
  });

  it('should process indicator that requires decay.', async () => {
    const logAppErrorSpy = vi.spyOn(logApp, 'error');
    const logAppWarnSpy = vi.spyOn(logApp, 'warn');
    await indicatorDecayHandler();
    expect(logAppErrorSpy, 'No error should be raised in normal behavior.').toHaveBeenCalledTimes(0);
    expect(logAppWarnSpy, 'No warn should be raised in normal behavior.').toHaveBeenCalledTimes(0);
  });

  it('should manage error in findIndicatorsForDecay', async () => {
    const logAppErrorSpy = vi.spyOn(logApp, 'error');
    const logAppWarnSpy = vi.spyOn(logApp, 'warn');
    await indicatorDecayHandler();
    // One record for the skipped indicator, one for the batch summary.
    expect(logAppWarnSpy, 'The skipped indicator and the batch summary should both be logged as warn.').toHaveBeenCalledTimes(2);
    expect(logAppErrorSpy, 'One indicator failing to decay is not an application error.').toHaveBeenCalledTimes(0);
  });
});
