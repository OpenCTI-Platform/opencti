import { describe, expect, it } from 'vitest';
import { v4 as uuidv4 } from 'uuid';
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

  const trackConcurrency = () => {
    const state = { calls: 0, running: 0, maxRunning: 0 };
    const trackedFunction = async () => {
      state.calls += 1;
      state.running += 1;
      state.maxRunning = Math.max(state.maxRunning, state.running);
      await wait(2000);
      state.running -= 1;
    };
    return { state, trackedFunction };
  };

  it('runFunctionAsLongRunning runs different executions concurrently', async () => {
    // Regression: the execution id was locked as a string, split into characters, so any two executions excluded each other
    const { state, trackedFunction } = trackConcurrency();
    const results = await Promise.all([
      runFunctionAsLongRunning(testContext, ADMIN_USER, trackedFunction, uuidv4()),
      runFunctionAsLongRunning(testContext, ADMIN_USER, trackedFunction, uuidv4()),
    ]);
    expect(results).toEqual([true, true]);
    expect(state.calls).toBe(2);
    expect(state.maxRunning).toBe(2);
  });

  it('runFunctionAsLongRunning never overlaps executions sharing a lock id', async () => {
    // Two messages for the same work (same lock id) must run one after the other, and both complete
    const { state, trackedFunction } = trackConcurrency();
    const lockId = uuidv4();
    const results = await Promise.all([
      runFunctionAsLongRunning(testContext, ADMIN_USER, trackedFunction, uuidv4(), lockId),
      runFunctionAsLongRunning(testContext, ADMIN_USER, trackedFunction, uuidv4(), lockId),
    ]);
    expect(results).toEqual([true, true]);
    // Both executions really run (the call state stays per execution), one after the other
    expect(state.calls).toBe(2);
    expect(state.maxRunning).toBe(1);
  });
});
