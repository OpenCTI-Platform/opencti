// read-files-script.js
const fs = require('fs');
const path = require('path');

// Specify the path to the source directory
const srcDirectory = 'src';
//Specify the name of the file
const englishTranslationFiles = 'lang/en.json';

// Define the pattern to search for in files
const searchPattern = /\{t\('[^']+'\)}/g;

// Object to store extracted key-value pairs
const extractedValues = {};

function extractValueFromPattern(pattern) {
  const match = /\{t\('([^']+)'\)\}/.exec(pattern);
  return match ? match[1] : null;
}

// Function to read files in a directory and its subdirectories
function extractI18nValues(directory) {
  fs.readdir(directory, (err, files) => {
    if (err) {
      console.error(`Error reading directory ${directory}: ${err.message}`);
    } else {
      files.forEach(file => {
        const filePath = path.join(directory, file);
        fs.stat(filePath, (statErr, stats) => {
          if (statErr) {
            console.error(`Error checking file ${filePath}: ${statErr.message}`);
          } else {
            if (stats.isDirectory()) {
              // If it's a directory, recursively call the function for that directory
              extractI18nValues(filePath);
            } else if (stats.isFile()) {
              // If it's a file, read and search for the pattern
              fs.readFile(filePath, 'utf8', (readErr, data) => {
                if (readErr) {
                  console.error(`Error reading file ${filePath}: ${readErr.message}`);
                } else {
                  // Use a regular expression to find all occurrences of the pattern {t('[...')}
                  const matches = data.match(searchPattern);
                  
                  if (matches) {
                    // Log the matches in the console
                    // console.log(`Matches in ${filePath}:`, matches);
                    matches.forEach(match => {
                      const value = extractValueFromPattern(match);
                      if (value) {
                        extractedValues[value] = value;
                      }
                    })
                  }
                }
              });
            }
          }
        });
      });
    }
  });
  
  fs.writeFile(englishTranslationFiles, JSON.stringify(extractedValues, null, 2), err => {
    if (err) {
      console.error(`Error writing to en.json: ${err.message}`);
    }
  });
}

// Call the function with the main source directory
extractI18nValues(srcDirectory);
