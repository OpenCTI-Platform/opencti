import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const getSchemaURL = () => {
  if (process.env.OPENCTI_MANIFEST_URL) {
    return process.env.OPENCTI_MANIFEST_URL;
  }

  if (process.env.TAG_VERSION) {
    return `https://raw.githubusercontent.com/OpenCTI-Platform/connectors/refs/tags/${process.env.TAG_VERSION}/manifest.json`;
  }
  // rolling
  return 'https://raw.githubusercontent.com/OpenCTI-Platform/connectors/refs/heads/master/manifest.json';
};
// use tags instead of master if env from circle TAG is set

const getFetchHeaders = () => {
  const headersEnv = process.env.OPENCTI_MANIFEST_HEADERS;
  return headersEnv ? JSON.parse(headersEnv) : {};
};

const OUTPUT_DIR = '../src/__generated__';
const OUTPUT_FILE = 'opencti-manifest.json';

const getConnectorManifest = async () => {
  console.info('📝 Getting connectors manifest');
  const schemaUrl = getSchemaURL();
  try {
    // fetch file
    console.info(`➡️ Fetching manifest from: ${schemaUrl}`);
    const res = await fetch(schemaUrl, {
      headers: getFetchHeaders(),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.text();

    // try to parse as json
    console.info('➡️ Parsing manifest...');
    JSON.parse(data);

    // save file
    console.info('➡️ Writing manifest file...');
    const fullDir = fileURLToPath(new URL(OUTPUT_DIR, import.meta.url));
    fs.mkdirSync(fullDir, { recursive: true });
    const fullPath = path.join(fullDir, OUTPUT_FILE);
    fs.writeFileSync(fullPath, data, 'utf8');

    console.info(`✅ Manifest saved to: ${fullPath}`);
  } catch (err) {
    console.error(`❌ Error: ${err.message}`, err);
    console.error(err);
    process.exit(1);
  }
};

await getConnectorManifest();
