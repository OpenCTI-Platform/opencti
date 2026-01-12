import { readdir, stat, readFile } from 'node:fs/promises';
import path from 'node:path';

const srcDirectoryFrontend = 'src';
const srcDirectoryBackend = '../opencti-graphql/src';
const englishTranslationFileFrontend = 'lang/front/en.json';
const englishTranslationFileBackend = 'lang/back/en.json';
const jsxTsxFileExtensions = ['.jsx', '.tsx'];
const jsTsFileExtensions = ['.js', '.ts'];
const frontendSearchPattern = /t_i18n\('[^']+'\)/g;
const backendSearchPattern = /label: '[^']+'/g;
const frontendExtractedValues = {};
const backendExtractedValues = {};
let missingTranslationsFrontend = 0;
let missingTranslationsBackend = 0;

const extractValueFromPatternFrontend = (pattern) => {
  const match = /t_i18n\('([^']+)'\)/.exec(pattern);
  return match ? match[1] : null;
}

const extractValueFromPatternBackend = (pattern) => {
  const match = /label: '([^']+)'/.exec(pattern);
  return match ? match[1] : null;
}

const extractI18nValuesFrontend = async (directory) => {
  try {
    const files = await readdir(directory);
    for (const file of files) {
      const filePath = path.join(directory, file);
      const stats = await stat(filePath);
      
      if (stats.isDirectory()) {
        await extractI18nValuesFrontend(filePath); // Recursively call the function for directories
      } else if (stats.isFile() && jsxTsxFileExtensions.includes(path.extname(filePath))) {
        const data = await readFile(filePath, 'utf8');
        const matches = data.match(frontendSearchPattern);
        if (matches) {
          matches.forEach(match => {
            const value = extractValueFromPatternFrontend(match);
            if (value) {
              frontendExtractedValues[value] = value;
            }
          });
        }
      }
    }
  } catch (error) {
    console.error(`Error: ${error.message}`);
  }
}

const extractI18nValuesBackend = async (directory) => {
  try {
    const files = await readdir(directory);
    for (const file of files) {
      const filePath = path.join(directory, file);
      const stats = await stat(filePath);
      
      if (stats.isDirectory()) {
        await extractI18nValuesBackend(filePath); // Recursively call the function for directories
      } else if (stats.isFile() && jsTsFileExtensions.includes(path.extname(filePath))) {
        const data = await readFile(filePath, 'utf8');
        const matches = data.match(backendSearchPattern);
        if (matches) {
          matches.forEach(match => {
            const value = extractValueFromPatternBackend(match);
            if (value) {
              backendExtractedValues[value] = value;
            }
          });
        }
      }
    }
  } catch (error) {
    console.error(`Error: ${error.message}`);
  }
}

const mergeWithExistingDataFrontend = async () => {
  try {
    const existingData = await readFile(englishTranslationFileFrontend, 'utf8');
    const existingValues = JSON.parse(existingData);
    
    const updatedValues = { ...existingValues };
    
    for (const key in frontendExtractedValues) {
      if (!updatedValues.hasOwnProperty(key)) {
        console.log('Missing frontend key: ' + key);
        missingTranslationsFrontend = 1
      }
    }
    
    console.log('Frontend file verified');
  } catch (error) {
    console.error(`Error merging frontend data: ${error.message}`);
  }
}

const mergeWithExistingDataBackend = async () => {
  try {
    const existingData = await readFile(englishTranslationFileBackend, 'utf8');
    const existingValues = JSON.parse(existingData);
    
    const updatedValues = { ...existingValues };
    
    for (const key in backendExtractedValues) {
      if (!updatedValues.hasOwnProperty(key)) {
        console.log('Missing backend key: ' + key);
        missingTranslationsBackend = 1
      }
    }
    console.log('Backend file verified');
  } catch (error) {
    console.error(`Error merging backend data: ${error.message}`);
  }
}

await extractI18nValuesFrontend(srcDirectoryFrontend);
await mergeWithExistingDataFrontend();

await extractI18nValuesBackend(srcDirectoryBackend);
await mergeWithExistingDataBackend();

const frontendResult = missingTranslationsFrontend ? 1 : 0;
const backendResult = missingTranslationsBackend ? 1 : 0;

process.exit(frontendResult + backendResult > 0 ? 1 : 0);
