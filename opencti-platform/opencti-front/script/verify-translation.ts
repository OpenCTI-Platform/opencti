import { readdir, stat, readFile } from 'node:fs/promises';
import path from 'node:path';

const srcDirectoryFrontend = 'src';
const srcDirectoryBackend = '../opencti-graphql/src';
const englishTranslationFileFrontend = 'lang/front/en.json';
const englishTranslationFileBackend = 'lang/back/en.json';
const jsxTsxFileExtensions = ['.jsx', '.tsx'];
const jsTsFileExtensions = ['.js', '.ts'];
const frontendSearchPattern = /t_i18n\('([^']+)'\)/g;
const backendSearchPattern = /label: '([^']+)'/g;
const frontendExtractedValues: Record<string, string> = {};
const backendExtractedValues: Record<string, string> = {};
let missingTranslationsFrontend = 0;
let missingTranslationsBackend = 0;

const extractI18nValuesFrontend = async (directory: string) => {
  try {
    const files = await readdir(directory);
    for (const file of files) {
      const filePath = path.join(directory, file);
      const stats = await stat(filePath);

      if (stats.isDirectory()) {
        await extractI18nValuesFrontend(filePath); // Recursively call the function for directories
      } else if (stats.isFile() && jsxTsxFileExtensions.includes(path.extname(filePath))) {
        const data = await readFile(filePath, 'utf8');
        for (const [, value] of data.matchAll(frontendSearchPattern)) {
          if (value) {
            frontendExtractedValues[value] = value;
          }
        }
      }
    }
  } catch (error) {
    console.error(`Error: ${(error instanceof Error ? error.message : String(error))}`);
  }
};

const extractI18nValuesBackend = async (directory: string) => {
  try {
    const files = await readdir(directory);
    for (const file of files) {
      const filePath = path.join(directory, file);
      const stats = await stat(filePath);

      if (stats.isDirectory()) {
        await extractI18nValuesBackend(filePath); // Recursively call the function for directories
      } else if (stats.isFile() && jsTsFileExtensions.includes(path.extname(filePath))) {
        const data = await readFile(filePath, 'utf8');
        for (const [, value] of data.matchAll(backendSearchPattern)) {
          if (value) {
            backendExtractedValues[value] = value;
          }
        }
      }
    }
  } catch (error) {
    console.error(`Error: ${(error instanceof Error ? error.message : String(error))}`);
  }
};

const mergeWithExistingDataFrontend = async () => {
  try {
    const existingData = await readFile(englishTranslationFileFrontend, 'utf8');
    const existingValues = JSON.parse(existingData);

    const updatedValues = { ...existingValues };

    for (const key in frontendExtractedValues) {
      if (!Object.prototype.hasOwnProperty.call(updatedValues, key)) {
        console.log('Missing frontend key: ' + key);
        missingTranslationsFrontend = 1;
      }
    }

    console.log('Frontend file verified');
  } catch (error) {
    console.error(`Error merging frontend data: ${(error instanceof Error ? error.message : String(error))}`);
  }
};

const mergeWithExistingDataBackend = async () => {
  try {
    const existingData = await readFile(englishTranslationFileBackend, 'utf8');
    const existingValues = JSON.parse(existingData);

    const updatedValues = { ...existingValues };

    for (const key in backendExtractedValues) {
      if (!Object.prototype.hasOwnProperty.call(updatedValues, key)) {
        console.log('Missing backend key: ' + key);
        missingTranslationsBackend = 1;
      }
    }
    console.log('Backend file verified');
  } catch (error) {
    console.error(`Error merging backend data: ${(error instanceof Error ? error.message : String(error))}`);
  }
};

await extractI18nValuesFrontend(srcDirectoryFrontend);
await mergeWithExistingDataFrontend();

await extractI18nValuesBackend(srcDirectoryBackend);
await mergeWithExistingDataBackend();

const frontendResult = missingTranslationsFrontend ? 1 : 0;
const backendResult = missingTranslationsBackend ? 1 : 0;

process.exit(frontendResult + backendResult > 0 ? 1 : 0);
