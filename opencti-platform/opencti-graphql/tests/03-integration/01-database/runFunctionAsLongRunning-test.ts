import { describe, expect, it } from 'vitest';
import { runFunctionAsLongRunning, wait } from '../../../src/database/utils';
import { ADMIN_USER, testContext } from '../../utils/testQuery';

describe('runFunctionAsLongRunning testing', () => {
  it('runFunctionAsLongRunning on fast functions', async () => {
    const fakeExecutionId = 'quick-function-call';
    const quickFunction = async () => {
      await wait(1000);
    };
    const firstCall = await runFunctionAsLongRunning(testContext, ADMIN_USER, quickFunction, fakeExecutionId);
    expect(firstCall).toBeTruthy();
    const secondCall = await runFunctionAsLongRunning(testContext, ADMIN_USER, quickFunction, fakeExecutionId);
    expect(secondCall).toBeTruthy();
  });

  it('runFunctionAsLongRunning on long running functions', async () => {
    const fakeExecutionId = 'long-function-call';
    const longRunningFunction = async () => {
      await wait(20000);
    };
    const firstCall = await runFunctionAsLongRunning(testContext, ADMIN_USER, longRunningFunction, fakeExecutionId);
    expect(firstCall).toBeFalsy();
    await wait(10000);
    const secondCall = await runFunctionAsLongRunning(testContext, ADMIN_USER, longRunningFunction, fakeExecutionId);
    expect(secondCall).toBeTruthy();
  });
});
