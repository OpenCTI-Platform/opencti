const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);

// deepl-free API key
const subscriptionKey = process.env.SUBSCRIPTION_KEY;

async function translateFiles() {
  console.log('Translation process started...');
  if (!subscriptionKey) {
    throw new Error('SUBSCRIPTION_KEY environment variable is not set. Aborting.');
  }

  try {
    // extract the available languages from the translation files name
    const langDir = './lang/front';
    const files = await fs.promises.readdir(langDir);
    const languageCodes = files
      .filter(file => file.endsWith('.json'))
      .map(file => path.basename(file, '.json'))
      .filter(code => code.length === 2 && code !== 'en'); // Exclude 'en' since it's the source
    console.log(`Translating from English to [${languageCodes}]`);

    for (const code of languageCodes) {
      const frontCommand = `i18n-auto-translation -a deepl-free -p ./lang/front/en.json -t ${code} -k ${subscriptionKey}`;
      const backCommand = `i18n-auto-translation -a deepl-free -p ./lang/back/en.json -t ${code} -k ${subscriptionKey}`;
      try {
        const { stdout } = await execAsync(frontCommand);
        console.log(stdout)
      } catch (error) {
        console.error(`Error translating ./lang/front/${code}.json:`, error.message);
      }
      try {
        const { stdout } = await execAsync(backCommand);
        console.log(stdout)
      } catch (error) {
        console.error(`Error translating ./lang/back/${code}.json:`, error.message);
      }
    }

    console.log('Translation process completed!');

  } catch (error) {
    console.error('Fatal error:', error.message);
    process.exit(1);
  }
}

// Run the script
translateFiles();
