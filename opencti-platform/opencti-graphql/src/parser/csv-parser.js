var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import fs from 'node:fs';
// import/no-unresolved https://github.com/import-js/eslint-plugin-import/issues/1810
// eslint-disable-next-line
import { parse } from 'csv-parse/sync';
import * as readline from 'readline';
import { Readable } from 'stream';
const parserOption = (delimiter) => ({
    delimiter,
    // https://csv.js.org/parse/options/
    relax_column_count: true,
});
const parseCsvFile = (filePath, delimiter) => {
    return new Promise((resolve, reject) => {
        const readLine = readline.createInterface({
            input: fs.createReadStream(filePath),
            crlfDelay: Infinity
        });
        const records = [];
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
            }
            catch (err) {
                reject(err);
            }
        });
    });
};
export const parseCsvBufferContent = (buffer, delimiter) => {
    return new Promise((resolve, reject) => {
        const readable = Readable.from(buffer);
        const chunks = [];
        readable.on('data', (chunk) => {
            chunks.push(new Uint8Array([...chunk]));
        })
            .on('error', (err) => {
            reject(err);
        })
            .on('end', () => {
            try {
                const parsing = parse(Buffer.concat(chunks).toString('utf8'), parserOption(delimiter));
                resolve(parsing);
            }
            catch (error) {
                reject(error);
            }
        });
    });
};
export const parsingProcess = (content, delimiter) => __awaiter(void 0, void 0, void 0, function* () {
    if (content instanceof Buffer) {
        return parseCsvBufferContent(content, delimiter);
    }
    return parseCsvFile(content, delimiter);
});
