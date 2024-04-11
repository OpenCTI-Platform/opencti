const fs = require('fs');
const util = require('util');
const path = require('path');

const readdir = util.promisify(fs.readdir);
const stat = util.promisify(fs.stat);
const readFile = util.promisify(fs.readFile);
const writeFile = util.promisify(fs.writeFile);

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

function extractValueFromPatternFrontend(pattern) {
  const match = /t_i18n\('([^']+)'\)/.exec(pattern);
  return match ? match[1] : null;
}

function extractValueFromPatternBackend(pattern) {
  const match = /label: '([^']+)'/.exec(pattern);
  return match ? match[1] : null;
}

async function extractI18nValuesFrontend(directory) {
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

async function extractI18nValuesBackend(directory) {
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

async function mergeWithExistingDataFrontend() {
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

async function mergeWithExistingDataBackend() {
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

async function main() {
  await extractI18nValuesFrontend(srcDirectoryFrontend);
  await mergeWithExistingDataFrontend();
  
  await extractI18nValuesBackend(srcDirectoryBackend);
  await mergeWithExistingDataBackend();
  
  const frontendResult = missingTranslationsFrontend ? 1 : 0;
  const backendResult = missingTranslationsBackend ? 1 : 0;
  
  return frontendResult + backendResult > 0 ? 1 : 0;
}

main().then(result => process.exit(result));
