const fs = require('fs');
const util = require('util');
const path = require('path');

const readdir = util.promisify(fs.readdir);
const stat = util.promisify(fs.stat);
const readFile = util.promisify(fs.readFile);
const writeFile = util.promisify(fs.writeFile);

const srcDirectory = '../opencti-graphql/src';
const englishTranslationFiles = 'lang/back/en.json';
const jsTsFileExtensions = ['.js', '.ts'];
const searchPattern = /label: '[^']+'/g;
const extractedValues = {};

// extract all the 'label' of attributes / relation refs from the backend schema
// and add them in opencti-front/lang/en-back.json

function extractValueFromPattern(pattern) {
  const match = /label: '([^']+)'/.exec(pattern);
  return match ? match[1] : null;
}

async function extractI18nValues(directory) {
  console.log('--- extract labels from backend schema definition ---');
  try {
    const files = await readdir(directory);
    for (const file of files) {
      const filePath = path.join(directory, file);
      const stats = await stat(filePath);

      if (stats.isDirectory()) {
        await extractI18nValues(filePath); // Recursively call the function for directories
      } else if (stats.isFile() && jsTsFileExtensions.includes(path.extname(filePath))) {
        const data = await readFile(filePath, 'utf8');
        const matches = data.match(searchPattern);

        console.log(filePath);
        console.log(matches);

        if (matches) {
          matches.forEach(match => {
            const value = extractValueFromPattern(match);
            if (value) {
              extractedValues[value] = value;
            }
          });
        }
      }
    }
  } catch (error) {
    console.error(`Error: ${error.message}`);
  }
}

async function mergeWithExistingData() {
  try {
    const existingData = await readFile(englishTranslationFiles, 'utf8');
    const existingValues = JSON.parse(existingData);

    const updatedValues = { ...existingValues };

    // Append only the new values that do not already exist in the file
    for (const key in extractedValues) {
      if (!updatedValues.hasOwnProperty(key)) {
        updatedValues[key] = extractedValues[key];
      }
    }
    // Write the merged values back to the file
    await writeFile(englishTranslationFiles, JSON.stringify(updatedValues, null, 2));
    console.log('File written successfully');
  } catch (error) {
    console.error(`Error merging with existing data: ${error.message}`);
  }
}

async function main() {
  await extractI18nValues(srcDirectory);
  await mergeWithExistingData();
}

main();
