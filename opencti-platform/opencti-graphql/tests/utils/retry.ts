import { wait } from '../../src/database/utils';

interface RetryUntilConditionOrMaxLoopArgs<T> {
  fnToExecute: () => Promise<T>,
  verify: (input: T) => boolean,
  sleepTimeBetweenLoop?: number,
  maxRetry?: number,
}

/**
 * Execute a function multiple times until the result of the function
 * makes the condition function to return true.
 *
 * Retry only a limited number of times, in case the condition is never
 * verified, the result of the last execution is returned.
 *
 * @param fnToExecute Function to execute to check the result.
 * @param verify Function to check the result of the last execution.
 * @param sleepTimeBetweenLoop Time in milliseconds between 2 executions.
 * @param maxRetry Max number of execution to do.
 */
export const retryUntilConditionOrMaxLoop = async <T = unknown>({
  fnToExecute,
  verify,
  sleepTimeBetweenLoop = 1000,
  maxRetry = 10
}: RetryUntilConditionOrMaxLoopArgs<T>) => {
  let result = await fnToExecute();
  let loopCurrent = 0;
  while (verify(result) && loopCurrent < maxRetry) {
    await wait(sleepTimeBetweenLoop);
    result = await fnToExecute();
    loopCurrent += 1;
  }
  return result;
};
