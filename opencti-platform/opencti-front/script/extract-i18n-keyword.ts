import { readdir, stat, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

const srcDirectory = 'src';
const englishTranslationFiles = 'lang/front/en.json';
const jsxTsxFileExtensions = ['.jsx', '.tsx'];
const t_i18nPatternSource = String.raw`t_i18n\((['"])((?:\\.|(?!\1).)*)\1\s*[,)]`;
const searchPattern = new RegExp(t_i18nPatternSource, 'g');
const labelSearchPattern = /label:\s'(\w+)',/g;
// Menu data (`*.entries.ts(x)` pages, navSections.tsx) declares its labels and search keywords as plain strings,
// translated at runtime with t_i18n(label) / t_i18n(keyword): there is no t_i18n('...') call to find in those files.
const menuDataFilePattern = /(\.entries\.tsx?|navSections\.tsx)$/;
const menuLabelPattern = /\blabel:\s*(['"])((?:\\.|(?!\1).)*)\1/g;
const menuKeywordsPattern = /\bkeywords:\s*\[([^\]]*)\]/g;
const stringLiteralPattern = /(['"])((?:\\.|(?!\1).)*)\1/g;
const extractedValues: Record<string, string> = {};

const addExtractedValue = (quote: string, captured: string) => {
  // unescape the quote char that was escaped for JS syntax reasons only
  const value = captured.replace(new RegExp(`\\\\${quote}`, 'g'), quote);
  if (value) {
    extractedValues[value] = value;
  }
};

// extract all translation in the t_i18n() formatter from frontend
// and add them in opencti-front/lang/en.json

const extractI18nValues = async (directory: string) => {
  try {
    const files = await readdir(directory);
    for (const file of files) {
      const filePath = path.join(directory, file);
      const stats = await stat(filePath);

      if (stats.isDirectory()) {
        await extractI18nValues(filePath); // Recursively call the function for directories
      } else if (stats.isFile() && (jsxTsxFileExtensions.includes(path.extname(filePath)) || menuDataFilePattern.test(filePath))) {
        const data = await readFile(filePath, 'utf8');
        if (menuDataFilePattern.test(filePath)) {
          for (const [, quote, captured] of data.matchAll(menuLabelPattern)) {
            addExtractedValue(quote, captured);
          }
          for (const [, keywords] of data.matchAll(menuKeywordsPattern)) {
            for (const [, quote, captured] of keywords.matchAll(stringLiteralPattern)) {
              addExtractedValue(quote, captured);
            }
          }
        }
        if (filePath === 'src\\components\\dataGrid\\dataTableUtils.tsx') {
          for (const [, value] of data.matchAll(labelSearchPattern)) {
            extractedValues[value] = value;
          }
        }
        for (const [, quote, captured] of data.matchAll(searchPattern)) {
          addExtractedValue(quote, captured);
        }
      }
    }
  } catch (error) {
    console.error(`Error: ${(error instanceof Error ? error.message : String(error))}`);
  }
};

const mergeWithExistingData = async () => {
  try {
    const existingData = await readFile(englishTranslationFiles, 'utf8');
    const existingValues = JSON.parse(existingData);

    const updatedValues = { ...existingValues };

    // Append only the new values that do not already exist in the file
    console.log('--- Add Frontend new key ---');
    for (const key in extractedValues) {
      if (!Object.prototype.hasOwnProperty.call(updatedValues, key)) {
        console.log(key);
        updatedValues[key] = extractedValues[key];
      }
    }
    console.log('--- End ---');
    // Write the merged values back to the file
    const sortedKeys = Object.keys(updatedValues).sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));
    const sortedValues: Record<string, string> = {};
    sortedKeys.forEach((key) => {
      sortedValues[key] = updatedValues[key];
    });
    await writeFile(englishTranslationFiles, JSON.stringify(sortedValues, null, 2));
    console.log('File written successfully');
  } catch (error) {
    console.error(`Error merging with existing data: ${(error instanceof Error ? error.message : String(error))}`);
  }
};

console.log('--- extract i18n values from frontend ---');
await extractI18nValues(srcDirectory);
await mergeWithExistingData();
