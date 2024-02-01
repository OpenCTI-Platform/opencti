import fs from 'node:fs';
// import/no-unresolved https://github.com/import-js/eslint-plugin-import/issues/1810
// eslint-disable-next-line
import { parse } from 'csv-parse/sync';
import * as readline from 'readline';
import { Readable } from 'stream';

const parserOption = (delimiter: string) => ({
  delimiter,
  // https://csv.js.org/parse/options/
  relax_column_count: true,
});

const parseCsvFile = (filePath: string, delimiter: string): Promise<string[][]> => {
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
          const parsing = parse(records.join(''), parserOption(delimiter));
          resolve(parsing);
        } catch (err) {
          reject(err);
        }
      });
  });
};

export const parseCsvBufferContent = (buffer: Buffer, delimiter: string): Promise<string[][]> => {
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
          const parsing = parse(Buffer.concat(chunks).toString('utf8'), parserOption(delimiter));
          resolve(parsing);
        } catch (error) {
          reject(error);
        }
      });
  });
};

export const parsingProcess = async (content: Buffer | string, delimiter: string): Promise<string[][]> => {
  if (content instanceof Buffer) {
    return parseCsvBufferContent(content, delimiter);
  }
  return parseCsvFile(content, delimiter);
};
