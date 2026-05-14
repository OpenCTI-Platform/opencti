import { describe, expect, it } from 'vitest';
import { runFunctionAsLongRunning, wait } from '../../../src/database/utils';
import { ADMIN_USER, testContext } from '../../utils/testQuery';

describe('runFunctionAsLongRunning testing', () => {
  it.concurrent('runFunctionAsLongRunning on fast functions', async () => {
    const fakeExecutionId = 'quick-function-call';
    const quickFunction = async () => {
      await wait(1000);
    };
    const firstCall = await runFunctionAsLongRunning(testContext, ADMIN_USER, quickFunction, fakeExecutionId);
    expect(firstCall).toBeTruthy();
    const secondCall = await runFunctionAsLongRunning(testContext, ADMIN_USER, quickFunction, fakeExecutionId);
    expect(secondCall).toBeTruthy();
  });

  it.concurrent('runFunctionAsLongRunning on long running functions', async () => {
    const fakeExecutionId = 'long-function-call';
    // Function needs to exceed the internal 10s timeout in runFunctionAsLongRunning
    const longRunningFunction = async () => {
      await wait(11000);
    };
    const firstCall = await runFunctionAsLongRunning(testContext, ADMIN_USER, longRunningFunction, fakeExecutionId);
    expect(firstCall).toBeFalsy();
    // Wait just enough for the background function to complete (11s - 10s timeout = 1s + margin)
    await wait(2000);
    const secondCall = await runFunctionAsLongRunning(testContext, ADMIN_USER, longRunningFunction, fakeExecutionId);
    expect(secondCall).toBeTruthy();
  });
});
