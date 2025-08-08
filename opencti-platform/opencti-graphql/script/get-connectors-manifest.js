import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import fetch from 'node-fetch';

const SCHEMA_URL = 'https://raw.githubusercontent.com/OpenCTI-Platform/connectors/refs/heads/oob/connector_manager/manifest.json';
const OUTPUT_DIR = '../src/modules/catalog/filigran';
const OUTPUT_FILE = 'opencti-manifest.json';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function getConnectorManifest() {
  try {
    console.log(`Fetching schema from: ${SCHEMA_URL}`);
    const res = await fetch(SCHEMA_URL);
    const data = await res.text();

    const fullDir = path.resolve(__dirname, OUTPUT_DIR);
    fs.mkdirSync(fullDir, { recursive: true });

    const fullPath = path.join(fullDir, OUTPUT_FILE);
    fs.writeFileSync(fullPath, data, 'utf8');

    console.log(`✅ Schema saved to: ${fullPath}`);
  } catch (err) {
    console.error(`❌ Error: ${err.message}`);
    process.exit(1);
  }
}

await getConnectorManifest();
