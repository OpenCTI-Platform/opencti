import fs from 'fs';
import * as R from 'ramda';

// OPTIMIZE: Currently assumes a Linux-based path separator; Will not work on Windows
const SEP = '/';

/**
 * Removes the path separator from the end of the given path string.
 *
 * @param path
 */
function noSep(path: string) {
  return path.endsWith(SEP) ? path.substring(0, -1) : path;
}

/**
 * Returns the nth parent directory path for the given path.
 * Returns null if there is no parent path or the given number of parents is greater than
 * existing parents.
 *
 * @param path - The starting path, preferably absolute
 * @param n - Number of parent directories to traverse up
 * @throws an error if n >= number of parent directories in path
 */
function parent(path: string, n = 1) {
  // OPTIMIZE: Currently assumes a Linux-based path separator; Will not work on Windows
  const pathBits = path.split(SEP);
  if (n >= pathBits.length - 1) {
    throw new Error(
      `parent of path ${path} could not be found because there are `
            + `not ${n} parent directories in the path string`,
    );
  }
  return R.take(pathBits.length - n, pathBits).join(SEP);
}

/**
 * Returns true if the given value is NOT its type's empty value. Returns false
 * otherwise.
 */
const notEmpty = (value: string) => (R.not(R.isEmpty(value)));

/**
 * Returns a path string built from an array of path parts.
 *
 * @param pathParts - A list of path strings to be joined together
 * @throws an error if pathParts is not an Array
 */
function buildPath(pathParts: Array<string>) {
  if (R.is(Array, pathParts)) {
    return pathParts.map(noSep).filter(notEmpty).join(SEP);
  }
  throw new Error('buildPath expects an Array of path parts');
}

/**
 * Returns the absolute path for a given filename. This is useful when uploading files to
 * file input elements in forms.
 *
 * @param fileName - File name to append to the absolute path
 * @param fromDir - A directory path relative to the current working directory
 * @returns
 */
export function getPath(fileName: string, fromDir: string) {
  return buildPath([process.cwd(), fromDir, fileName]);
}

/**
 * Returns an absolute path for a selenium testing resource. Default path for resourceDir
 * is 'src/__tests__/selenium/resources'.
 */
export function getResourcePath(fileName: string, resourceDir = 'src/__tests__/selenium/resources') {
  return getPath(fileName, resourceDir);
}

/**
 * Returns the absolute path to a file in the opencti-graphql directory. This is a
 * sibling to the current working directory. An optional path relative to the graphql
 * directory can also be provided.
 *
 * @param fileName - File name to append to the absolute path
 * @param gqlDir - Optional relative path inside opencti-graphql
 */
export function getGQLPath(fileName: string, gqlDir = '') {
  return buildPath([parent(process.cwd()), 'opencti-graphql', gqlDir, fileName]);
}

/**
 * Reads and parses the contents of a JSON file. Returns the contents as an object.
 */
export function readJsonFile(filePath: string) {
  const error_data = '{"error":"NOT_FOUND"}';
  let returnValue = JSON.parse(error_data);
  // Check that the file requested exists
  if (!fs.existsSync(filePath)) {
    /* eslint-disable no-console */
    const err_msg = `ERROR: File not found ${filePath}`;
    console.log('#'.repeat(err_msg.length));
    console.log(err_msg);
    console.log('#'.repeat(err_msg.length));
    /* eslint-enable no-console */
  } else {
    const rawData = fs.readFileSync(filePath);
    returnValue = JSON.parse(rawData.toString('utf8'));
  }
  return returnValue;
}

/**
 * Reads the contents of the given config file from the config directory. Returns a
 * config object.
 */
export function readConfigFile(configName = 'development.json') {
  let returnValue = readJsonFile(getGQLPath(configName, 'config'));
  if (('error' in returnValue) && (returnValue.error === 'NOT_FOUND')) {
    /* eslint-disable no-console */
    const err_msg = `WARN: Config file ${configName} not found. Trying test.json`;
    console.log('#'.repeat(err_msg.length));
    console.log(err_msg);
    console.log('#'.repeat(err_msg.length));
    /* eslint-enable no-console */
    returnValue = readJsonFile(getGQLPath('test.json', 'config'));
  }
  if (('error' in returnValue) && (returnValue.error === 'NOT_FOUND')) {
    /* eslint-disable no-console */
    const err_msg = 'ERROR: Configuration file not found! Need a config/development.json or config/test.json';
    console.log('#'.repeat(87));
    console.log(err_msg);
    console.log('#'.repeat(87));
    /* eslint-enable no-console */
    // eslint-disable-next-line @typescript-eslint/no-throw-literal
    throw err_msg;
  }
  return returnValue;
}
