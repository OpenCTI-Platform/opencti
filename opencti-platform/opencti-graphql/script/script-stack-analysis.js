import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { SourceMapConsumer } from 'source-map';

const readStdin = () => new Promise((resolve) => {
  let data = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => {
    data += chunk;
  });
  process.stdin.on('end', () => resolve(data));
});

/**
 * This code will allow you to convert a built stack error to the real lines of code
 * For that you need to align your code version and build the backend/frontend to have the correct back.mjs.map file
 * For the backend, <yarn build> in opencti-graphql
 * For the frontend, <yarn build> in opencti-front
 * Then you just have to put your json log of the error in a .env files at the root directory of opencti-graphql
 * .env => backend_log='{...}' or frontend_log='{...}'
 * and start the script yarn stack:analysis
 */

const BACKEND_MAP = './build/back.mjs.map';
const FRONT_ASSETS_DIR = '../opencti-front/dist/assets';
const isExecTypeBack = process.argv[process.argv.length - 1] === 'back';
const stackData = (isExecTypeBack ? process.env.BACKEND_LOG : process.env.FRONTEND_LOG) ?? await readStdin();

let sourceMapContents;
if (isExecTypeBack) {
  const sourceMapFile = await readFile(BACKEND_MAP, 'utf8');
  sourceMapContents = [JSON.parse(sourceMapFile)];
} else {
  const files = await readdir(FRONT_ASSETS_DIR);
  const mapFiles = files.filter((f) => f.endsWith('.js.map'));
  sourceMapContents = await Promise.all(
    mapFiles.map(async (f) => JSON.parse(await readFile(join(FRONT_ASSETS_DIR, f), 'utf8')))
  );
}

const specificErrorKeys = ['componentStack', 'codeStack'];
const specificStartErrorMessages = ['Error', 'GraphQLError', 'TypeError'];
const getAllLogStacks = (obj, results = []) => {
  if (typeof obj === 'object' && obj !== null) {
    for (const key in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, key)) {
        const value = obj[key];
        if (typeof value === 'string' && (specificErrorKeys.includes(key) || specificStartErrorMessages.some((m) => value.startsWith(m)))) {
          results.push(value);
        } else if (typeof value === 'object') {
          getAllLogStacks(value, results);
        }
      }
    }
  }
  return results;
};

const parseStackTrace = async (stackTrace, sourceMaps) => {
  const consumers = await Promise.all(sourceMaps.map((sm) => new SourceMapConsumer(sm)));
  const lines = stackTrace.split('\n');
  const mappedLines = lines.map((line) => {
    // Updated regular expression to handle both formats
    const match = line.match(/at\s+(.+?)\s+\((.+):(\d+):(\d+)\)|at\s+(.+):(\d+):(\d+)/);
    if (match) {
      if (match[1]) {
        // Format: at functionName (file:line:column)
        const [, functionName,, lineNumber, columnNumber] = match;
        for (const consumer of consumers) {
          const originalPosition = consumer.originalPositionFor({
            line: parseInt(lineNumber, 10),
            column: parseInt(columnNumber, 10),
          });
          if (originalPosition.source) {
            return `at ${functionName} (${originalPosition.source}:${originalPosition.line}:${originalPosition.column})`;
          }
        }
      } else {
        // Format: at file:line:column
        const [, lineNumber, columnNumber] = match.slice(5);
        for (const consumer of consumers) {
          const originalPosition = consumer.originalPositionFor({
            line: parseInt(lineNumber, 10),
            column: parseInt(columnNumber, 10),
          });
          if (originalPosition.source) {
            return `at ${originalPosition.source}:${originalPosition.line}:${originalPosition.column}`;
          }
        }
      }
    }
    return line;
  });
  consumers.forEach((c) => c.destroy());
  return mappedLines.join('\n');
};

const traces = getAllLogStacks(JSON.parse(stackData));
for (let i = 0; i < traces.length; i += 1) {
  const stackTrace = traces[i];
  try {
    console.log(await parseStackTrace(stackTrace, sourceMapContents));
  } catch (error) {
    console.error(error);
  }
}
