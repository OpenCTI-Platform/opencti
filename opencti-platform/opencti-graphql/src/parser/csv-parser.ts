import fs from 'node:fs';
// import/no-unresolved https://github.com/import-js/eslint-plugin-import/issues/1810
// eslint-disable-next-line
import { parse } from 'csv-parse/sync';
import * as readline from 'readline';
import { Readable } from 'stream';
import { logApp } from '../config/conf';
import { isNotEmptyField } from '../database/utils';

const parserOption = (delimiter: string, comment: string) => ({
  delimiter,
  comment,
  comment_no_infix: true,
  // https://csv.js.org/parse/options/
  relax_column_count: true,
});

const parseCsvFile = (filePath: string, delimiter: string, skipLineChar: string): Promise<string[][]> => {
  return new Promise((resolve, reject) => {
    const readLine = readline.createInterface({
      input: fs.createReadStream(filePath),
      crlfDelay: Infinity
    });
    const records: string[] = [];
    readLine.on('line', (line) => {
      records.push(`${line}\n`);
    })
      .on('error', (err) => {
        reject(err);
      })
      .on('close', () => {
        try {
          const parsing = parse(records.join(''), parserOption(delimiter, skipLineChar));
          resolve(parsing);
        } catch (err) {
          reject(err);
        }
      });
  });
};

export const parseCsvBufferContent = (buffer: Buffer, delimiter: string, skipLineChar: string): Promise<string[][]> => {
  return new Promise((resolve, reject) => {
    const readable = Readable.from(buffer);
    const chunks: Uint8Array[] = [];
    readable.on('data', (chunk: Uint8Array) => {
      chunks.push(new Uint8Array([...chunk]));
    })
      .on('error', (err) => {
        reject(err);
      })
      .on('end', () => {
        try {
          const parsingResult = [];
          const data = Buffer.concat(chunks).toString('utf8');
          const lines = data.split('\n');
          for (let index = 0; index < lines.length; index += 1) {
            const line = lines[index];
            try {
              const parsing = parse(line, parserOption(delimiter, skipLineChar));
              if (isNotEmptyField(parsing[0])) {
                parsingResult.push(parsing[0]);
              }
            } catch (err) {
              logApp.error('Error parsing CSV line', { line, cause: err });
            }
          }
          resolve(parsingResult);
        } catch (error) {
          reject(error);
        }
      });
  });
};

export const parsingProcess = async (content: Buffer | string, delimiter: string, skipLineChar: string): Promise<string[][]> => {
  if (content instanceof Buffer) {
    return parseCsvBufferContent(content, delimiter, skipLineChar);
  }
  return parseCsvFile(content, delimiter, skipLineChar);
};
