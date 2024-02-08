import { describe, it, vi, expect } from 'vitest';
import { indicatorDecayHandler } from '../../../src/manager/indicatorDecayManager';
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
describe('Testing indicatorDecayManager', () => {
  vi.mock('../../../src/modules/indicator/indicator-domain', () => {
    return {
      findIndicatorsForDecay: vi.fn()
        .mockImplementation(() => { return indicatorList; }),
      updateIndicatorDecayScore: vi.fn()
        .mockImplementationOnce(() => { /* Do nothing */ })
        .mockImplementationOnce(() => {
          throw new Error('Second time test is throwing error');
        }),
    };
  });

  it('should process indicator that requires decay.', async () => {
    const logAppErrorSpy = vi.spyOn(logApp, 'error');
    const logAppWarnSpy = vi.spyOn(logApp, 'warn');
    await indicatorDecayHandler();
    expect(logAppErrorSpy, 'No error should be raised in normal behavior.').toHaveBeenCalledTimes(0);
    expect(logAppWarnSpy, 'No warn should be raised in normal behavior.').toHaveBeenCalledTimes(0);
  });

  it('should manage error in findIndicatorsForDecay', async () => {
    const logAppWarnSpy = vi.spyOn(logApp, 'warn');
    await indicatorDecayHandler();
    expect(logAppWarnSpy, 'Error should be managed and log as warn.').toHaveBeenCalledTimes(1);
  });
});
