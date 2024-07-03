// import/no-unresolved https://github.com/import-js/eslint-plugin-import/issues/1810
// eslint-disable-next-line
import { parse } from 'csv-parse/sync';
import * as readline from 'readline';

const parserOption = (delimiter: string, comment?: string) => ({
  delimiter,
  comment,
  comment_no_infix: true,
  // https://csv.js.org/parse/options/
  relax_column_count: true,
});

export const parseReadableToLines = async (input: NodeJS.ReadableStream, maxRecordNumber?: number): Promise<string[]> => {
  const records: string[] = [];
  const rl = readline.createInterface({ input, crlfDelay: 5000 });
  // Need an async interator to prevent blocking
  // eslint-disable-next-line no-restricted-syntax
  for await (const line of rl) {
    records.push(line);
    if (maxRecordNumber && records.length > maxRecordNumber) {
      break;
    }
  }
  return records;
};

export const parsingProcess = async (lines: string[], delimiter: string, skipLineChar?: string): Promise<string[][]> => {
  return parse(lines.join('\n'), parserOption(delimiter, skipLineChar));
};
