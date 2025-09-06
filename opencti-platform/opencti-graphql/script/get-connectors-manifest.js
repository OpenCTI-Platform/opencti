import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const SCHEMA_URL = 'https://raw.githubusercontent.com/OpenCTI-Platform/connectors/refs/heads/master/manifest.json';

const OUTPUT_DIR = '../src/__generated__';
const OUTPUT_FILE = 'opencti-manifest.json';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function getConnectorManifest() {
  try {
    console.info(`Fetching manifest from: ${SCHEMA_URL}`);
    const res = await fetch(SCHEMA_URL);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.text();

    JSON.parse(data);

    const fullDir = path.resolve(__dirname, OUTPUT_DIR);
    fs.mkdirSync(fullDir, { recursive: true });
    const fullPath = path.join(fullDir, OUTPUT_FILE);
    fs.writeFileSync(fullPath, data, 'utf8');

    console.info(`✅ Manifest saved to: ${fullPath}`);
  } catch (err) {
    console.error(`❌ Error: ${err.message}`);
    process.exit(1);
  }
}

await getConnectorManifest();
