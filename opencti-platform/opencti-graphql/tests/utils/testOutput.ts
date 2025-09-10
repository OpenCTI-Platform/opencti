import fs from 'node:fs';
import { join } from 'node:path';
import { wait } from '../../src/database/utils';
import type { BasicObject } from '../../src/generated/graphql';

const TEST_OUTPUT_FOLDER = 'test-results';

/**
 * Write content to a folder that will be archived at the end of test in CI.
 * @param fileContent
 * @param filename
 */
export const writeTestDataToFile = (fileContent: string, filename: string) => {
  if (!fs.existsSync(TEST_OUTPUT_FOLDER)) {
    fs.mkdirSync(TEST_OUTPUT_FOLDER, { recursive: true });
  }
  const filePath = join(TEST_OUTPUT_FOLDER, filename);
  fs.writeFileSync(filePath, fileContent, {});
};

/**
 * try a condition several times until it's verified or the max number of loop is done
 * to avoid using wait(TIME) and save time if the condition is verified sooner
 * @param conditionPromise: the condition to verify
 * @param testCondition: the function to test if the condition is verified
 * @param sleepTimeBetweenLoop: the time to wait between 2 loops
 * @param loopCount: the number of loops to do
 */
export const retryUntilConditionOrMaxLoop = async <T extends BasicObject>(
  conditionPromise: () => Promise<T>,
  testCondition: (input: T) => boolean,
  sleepTimeBetweenLoop = 1000,
  loopCount = 10,
) => {
  let result = await conditionPromise();
  let loopCurrent = 0;
  while (testCondition(result) && loopCurrent < loopCount) {
    await wait(sleepTimeBetweenLoop);
    result = await conditionPromise();
    loopCurrent += 1;
  }
  return result;
};
