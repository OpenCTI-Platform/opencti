/* eslint-disable no-console */
import { readFileSync } from 'fs';
import { SourceMapConsumer } from 'source-map';

/**
 * This code will allow you to convert a built stack error to the real lines of code
 * For that you need to align your code version and build the backend/frontend to have the correct back.js.map file
 * For the backend, <yarn build> in opencti-graphql
 * For the frontend, <yarn build:standalone> in opencti-front
 * Then you just have to put your json log of the error in a .env files at the root directory of opencti-graphql
 * .env => backend_log='{...}' or frontend_log='{...}'
 * and start the script yarn stack:analysis
 */

const BACKEND_MAP = './build/back.js.map';
const FRONT_MAP = '../opencti-front/builder/prod/build/static/js/front.js.map';
const isExecTypeBack = process.argv[process.argv.length - 1] === 'back';
const stackData = isExecTypeBack ? process.env.BACKEND_LOG : process.env.frontend_log;

const sourceMapFile = readFileSync(isExecTypeBack ? BACKEND_MAP : FRONT_MAP, 'utf8');
const sourceMapContent = JSON.parse(sourceMapFile);

const specificErrorKeys = ['componentStack', 'codeStack'];
const specificStartErrorMessages = ['Error', 'GraphQLError', 'TypeError'];
const getAllLogStacks = (obj, results = []) => {
  if (typeof obj === 'object' && obj !== null) {
    // eslint-disable-next-line no-restricted-syntax
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

const parseStackTrace = async (stackTrace, sourceMap) => {
  const consumer = await new SourceMapConsumer(sourceMap);
  const lines = stackTrace.split('\n');
  const mappedLines = lines.map((line) => {
    // Updated regular expression to handle both formats
    const match = line.match(/at\s+(.+?)\s+\((.+):(\d+):(\d+)\)|at\s+(.+):(\d+):(\d+)/);
    if (match) {
      if (match[1]) {
        // Format: at functionName (file:line:column)
        const [, functionName,, lineNumber, columnNumber] = match;
        const originalPosition = consumer.originalPositionFor({
          line: parseInt(lineNumber, 10),
          column: parseInt(columnNumber, 10)
        });
        if (originalPosition.source) {
          return `at ${functionName} (${originalPosition.source}:${originalPosition.line}:${originalPosition.column})`;
        }
      } else {
        // Format: at file:line:column
        const [, lineNumber, columnNumber] = match.slice(5);
        const originalPosition = consumer.originalPositionFor({
          line: parseInt(lineNumber, 10),
          column: parseInt(columnNumber, 10)
        });
        if (originalPosition.source) {
          return `at ${originalPosition.source}:${originalPosition.line}:${originalPosition.column}`;
        }
      }
    }
    return line;
  });
  consumer.destroy();
  return mappedLines.join('\n');
};

const traces = getAllLogStacks(JSON.parse(stackData));
for (let i = 0; i < traces.length; i += 1) {
  const stackTrace = traces[i];
  parseStackTrace(stackTrace, sourceMapContent).then((mappedStackTrace) => {
    console.log(mappedStackTrace);
  }).catch((err) => {
    console.error(err);
  });
}
