import { readdir, stat, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

const srcDirectory = '../opencti-graphql/src';
const englishTranslationFiles = 'lang/back/en.json';
const jsTsFileExtensions = ['.js', '.ts'];
const searchPattern = /label: '([^']+)'/g;
const extractedValues: Record<string, string> = {};

// extract all the 'label' of attributes / relation refs from the backend schema
// and add them in opencti-front/lang/en-back.json

const extractI18nValues = async (directory: string) => {
  try {
    const files = await readdir(directory);
    for (const file of files) {
      const filePath = path.join(directory, file);
      const stats = await stat(filePath);

      if (stats.isDirectory()) {
        await extractI18nValues(filePath); // Recursively call the function for directories
      } else if (stats.isFile() && jsTsFileExtensions.includes(path.extname(filePath))) {
        const data = await readFile(filePath, 'utf8');
        for (const [, value] of data.matchAll(searchPattern)) {
          if (value) {
            extractedValues[value] = value;
          }
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
    console.log('--- Add Backend new key ---');
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

console.log('--- extract labels from backend schema definition ---');
await extractI18nValues(srcDirectory);
await mergeWithExistingData();
