import fs from 'node:fs';
import { join } from 'node:path';

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
