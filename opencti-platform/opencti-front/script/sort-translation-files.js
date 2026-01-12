import { readFile, readdirSync } from 'node:fs/promises';
import path from 'node:path';

const sortJSONKeys = (json) => {
  const sortedKeys = Object.keys(json).sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));
  const sortedJSON = {};
  sortedKeys.forEach((key) => {
    sortedJSON[key] = json[key];
  });
  return sortedJSON;
}

const sortJSONFile = async (filePath) => {
  try {
    // Read JSON file
    const jsonData = JSON.parse(await readFile(filePath, 'utf8'));
    
    // Sort JSON keys
    const sortedJSON = sortJSONKeys(jsonData);
    
    // Write back to the file
    fs.writeFileSync(filePath, JSON.stringify(sortedJSON, null, 2));
    
    console.log(`JSON file "${filePath}" has been sorted successfully.`);
  } catch (err) {
    console.error(`Error sorting JSON file "${filePath}":`, err);
  }
}

const sortAllJSONFiles = async (dirPath) => {
  try {
    // Get list of files in directory
    const files = await readdirSync(dirPath);
    
    // Iterate through files
    files.forEach((file) => {
      const filePath = path.join(dirPath, file);
      
      // Skip if not a JSON file or if it's en.json
      if (!file.endsWith('.json')) {
        return;
      }
      
      // Sort JSON file
      sortJSONFile(filePath);
    });
  } catch (err) {
    console.error('Error reading directory:', err);
  }
}

await sortAllJSONFiles('lang/front');
await sortAllJSONFiles('lang/back');
