const fs = require('fs');
const path = require('path');

// Check if OpenAI package is available (for Z.AI)
let OpenAI;
try {
  OpenAI = require('openai');
} catch (error) {
  console.error('⚠️  OpenAI package not found. Please install it: npm install openai');
  process.exit(1);
}

const BATCH_SIZE = 100;
const CONCURRENCY = 4;

// Get API key from environment variable
const ZAI_API_KEY = process.env.ZAI_API_KEY;
const ZAI_BASE_URL = process.env.ZAI_BASE_URL || 'https://api.z.ai/api/coding/paas/v4';

if (!ZAI_API_KEY) {
  console.error('❌ ZAI_API_KEY environment variable is not set.');
  console.error('   Please set it: export ZAI_API_KEY=your_api_key');
  process.exit(1);
}

// Initialize Z.AI client
const client = new OpenAI({
  apiKey: ZAI_API_KEY,
  baseURL: ZAI_BASE_URL,
});

/**
 * Translate a batch of key-value pairs
 */
async function translateBatch(batch) {
  const prompt = `You are a professional translator. Translate the following JSON key-value pairs from English to Persian (Farsi). 
Keep the keys identical and return valid JSON only. Do not add any explanations, just return the JSON object.
${JSON.stringify(batch, null, 2)}`;

  try {
    const res = await client.chat.completions.create({
      model: 'glm-4.6',
      messages: [
        { 
          role: 'system', 
          content: 'You are a professional translator specializing in English to Persian (Farsi) translation. Always return valid JSON only.' 
        },
        { role: 'user', content: prompt }
      ],
      temperature: 0
    });
    
    const text = res.choices[0].message.content;
    // Remove markdown code blocks if present
    const cleanedText = text.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
    return JSON.parse(cleanedText);
  } catch (error) {
    console.error('Error in translateBatch:', error.message);
    throw error;
  }
}

/**
 * Run translation in batches with concurrency
 */
async function runBatches(keysToTranslate, enContent) {
  if (keysToTranslate.length === 0) {
    console.log('   No keys to translate.');
    return {};
  }

  console.log(`   Translating ${keysToTranslate.length} keys in batches...`);
  
  const batches = [];
  for (let i = 0; i < keysToTranslate.length; i += BATCH_SIZE) {
    const batch = {};
    keysToTranslate.slice(i, i + BATCH_SIZE).forEach(k => {
      batch[k] = enContent[k];
    });
    batches.push(batch);
  }

  console.log(`   Created ${batches.length} batch(es)`);

  const results = {};
  let i = 0;

  async function worker() {
    while (i < batches.length) {
      const index = i++;
      try {
        console.log(`   Processing batch ${index + 1}/${batches.length}...`);
        const translated = await translateBatch(batches[index]);
        Object.assign(results, translated);
        console.log(`   ✅ Batch ${index + 1} completed`);
      } catch (error) {
        console.error(`   ⚠️  Error in batch ${index + 1}:`, error.message);
        // On error, keep original values for that batch
        Object.keys(batches[index]).forEach(key => {
          results[key] = batches[index][key];
        });
      }
    }
  }

  const workers = Array.from({ length: CONCURRENCY }, () => worker());
  await Promise.all(workers);

  return results;
}

/**
 * Find differences between current and baseline English files
 */
function findDifferences(current, baseline) {
  const newKeys = [];
  const changedKeys = [];
  const removedKeys = [];

  // Find new and changed keys
  for (const key in current) {
    if (!(key in baseline)) {
      newKeys.push(key);
    } else if (current[key] !== baseline[key]) {
      changedKeys.push(key);
    }
  }

  // Find removed keys
  for (const key in baseline) {
    if (!(key in current)) {
      removedKeys.push(key);
    }
  }

  return { newKeys, changedKeys, removedKeys };
}

/**
 * Translate a JSON file from English to Persian using Z.AI
 */
async function translateFile(enFilePath, faFilePath, baselineDir = null) {
  console.log(`\n   📄 Processing: ${path.basename(enFilePath)}`);
  
  if (!fs.existsSync(enFilePath)) {
    console.error(`   ❌ File not found: ${enFilePath}`);
    return false;
  }

  try {
    // Read current English file
    const enCurrent = JSON.parse(fs.readFileSync(enFilePath, 'utf8'));
    const enKeys = Object.keys(enCurrent);
    
    console.log(`   📊 Total keys in English: ${enKeys.length}`);

    // Read baseline English file if baseline directory is provided
    let enBaseline = {};
    let useBaseline = false;
    if (baselineDir) {
      // Create unique baseline filename based on parent directory (front/back) and filename
      const parentDir = path.basename(path.dirname(enFilePath));
      const fileName = path.basename(enFilePath, '.json');
      const baselineFileName = `${parentDir}-${fileName}.json`;
      const baselinePath = path.join(baselineDir, baselineFileName);
      
      if (fs.existsSync(baselinePath)) {
        try {
          enBaseline = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));
          useBaseline = true;
          console.log(`   📋 Baseline found, will detect changes`);
        } catch (error) {
          console.log(`   ⚠️  Baseline file corrupted, will use full comparison`);
        }
      } else {
        console.log(`   📝 No baseline found, first run - will translate all keys`);
      }
    }

    // Read existing Persian file if it exists
    let faContent = {};
    if (fs.existsSync(faFilePath)) {
      try {
        faContent = JSON.parse(fs.readFileSync(faFilePath, 'utf8'));
        console.log(`   📋 Existing Persian translations: ${Object.keys(faContent).length} keys`);
      } catch (error) {
        console.log(`   ⚠️  Existing Persian file is corrupted, starting fresh...`);
        faContent = {};
      }
    }

    // Find keys that need translation:
    let keysToTranslate = [];
    const newKeys = [];
    const untranslatedKeys = [];
    const changedKeys = [];

    if (useBaseline) {
      // Use baseline to detect changes
      const { newKeys: baselineNew, changedKeys: baselineChanged } = findDifferences(enCurrent, enBaseline);
      
      // Keys to translate:
      // 1. New keys (not in baseline)
      // 2. Changed keys (English text changed)
      // 3. Keys that exist in Persian but are untranslated (same as English)
      for (const key of enKeys) {
        if (baselineNew.includes(key)) {
          // New key
          keysToTranslate.push(key);
          newKeys.push(key);
        } else if (baselineChanged.includes(key)) {
          // English text changed
          keysToTranslate.push(key);
          changedKeys.push(key);
        } else if (key in faContent && faContent[key] === enCurrent[key]) {
          // Exists in Persian but untranslated (same as English)
          keysToTranslate.push(key);
          untranslatedKeys.push(key);
        }
      }
    } else {
      // No baseline - use simple comparison
      for (const key of enKeys) {
        if (!(key in faContent)) {
          // New key - doesn't exist in Persian file
          keysToTranslate.push(key);
          newKeys.push(key);
        } else if (faContent[key] === enCurrent[key]) {
          // Key exists but value is same as English (not translated, likely copied)
          keysToTranslate.push(key);
          untranslatedKeys.push(key);
        }
      }
    }

    if (keysToTranslate.length === 0) {
      console.log(`   ✅ All keys are already translated!`);
      return true;
    }

    console.log(`   🔄 Keys to translate: ${keysToTranslate.length}`);
    if (newKeys.length > 0) {
      console.log(`      - New keys: ${newKeys.length}`);
    }
    if (untranslatedKeys.length > 0) {
      console.log(`      - Untranslated keys (same as English): ${untranslatedKeys.length}`);
    }

    // Translate keys that need translation
    const translated = await runBatches(keysToTranslate, enCurrent);

    // Merge translations
    Object.assign(faContent, translated);

    // Remove keys that no longer exist in English file
    const faKeys = Object.keys(faContent);
    const removedKeys = faKeys.filter(key => !(key in enCurrent));
    removedKeys.forEach(key => {
      delete faContent[key];
    });

    if (removedKeys.length > 0) {
      console.log(`   🗑️  Removed ${removedKeys.length} obsolete key(s)`);
    }

    // Update baseline if baseline directory is provided
    if (baselineDir) {
      const parentDir = path.basename(path.dirname(enFilePath));
      const fileName = path.basename(enFilePath, '.json');
      const baselineFileName = `${parentDir}-${fileName}.json`;
      const baselinePath = path.join(baselineDir, baselineFileName);
      fs.writeFileSync(baselinePath, JSON.stringify(enCurrent, null, 2), 'utf8');
      console.log(`   💾 Baseline updated`);
    }

    // Save Persian file
    fs.writeFileSync(faFilePath, JSON.stringify(faContent, null, 2), 'utf8');
    console.log(`   ✅ Translation completed: ${Object.keys(translated).length} key(s) translated`);
    
    return true;
  } catch (error) {
    console.error(`   ❌ Error processing file:`, error.message);
    return false;
  }
}

/**
 * Main function
 */
async function main() {
  console.log('🚀 Starting translation with Z.AI API...\n');

  const scriptDir = __dirname;
  const langDir = path.join(scriptDir, '../lang');
  const baselineDir = path.join(scriptDir, './local');
  
  // Create baseline directory if it doesn't exist
  if (!fs.existsSync(baselineDir)) {
    fs.mkdirSync(baselineDir, { recursive: true });
  }
  
  const enFrontPath = path.join(langDir, 'front/en.json');
  const faFrontPath = path.join(langDir, 'front/fa.json');
  const enBackPath = path.join(langDir, 'back/en.json');
  const faBackPath = path.join(langDir, 'back/fa.json');

  const results = await Promise.all([
    translateFile(enFrontPath, faFrontPath, baselineDir),
    translateFile(enBackPath, faBackPath, baselineDir),
  ]);

  if (results.every(r => r)) {
    console.log('\n✨ Translation completed successfully!');
    return 0;
  } else {
    console.log('\n⚠️  Translation completed with some errors.');
    return 1;
  }
}

// Run if called directly
if (require.main === module) {
  main().then(code => process.exit(code)).catch(error => {
    console.error('\n❌ Fatal error:', error.message);
    process.exit(1);
  });
}

// Export for use in other scripts
module.exports = { translateFile, main, findDifferences };

