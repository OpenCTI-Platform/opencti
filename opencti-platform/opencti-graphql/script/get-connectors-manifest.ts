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

const MAX_ATTEMPTS = 5;
const RETRY_DELAY_MS = 2000;
const RETRYABLE_STATUSES = new Set([408, 429, 500, 502, 503, 504]);

const sleep = (ms: number) => new Promise((resolve) => {
  setTimeout(resolve, ms);
});

// A transient network reset or a 5xx from GitHub must not fail the build: retry
// those, fail at once on any other HTTP error.
const fetchManifest = async (url: string): Promise<string> => {
  let lastError: unknown;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt += 1) {
    try {
      const res = await fetch(url, { headers: getFetchHeaders() });
      if (res.ok) return await res.text();
      lastError = new Error(`HTTP ${res.status}`);
      if (!RETRYABLE_STATUSES.has(res.status)) throw lastError;
    } catch (err) {
      if (err === lastError) throw err;
      lastError = err;
    }
    if (attempt < MAX_ATTEMPTS) {
      console.warn(`⚠️ Attempt ${attempt}/${MAX_ATTEMPTS} failed (${lastError instanceof Error ? lastError.message : String(lastError)}), retrying`);
      await sleep(RETRY_DELAY_MS * attempt);
    }
  }
  throw lastError;
};

const OUTPUT_DIR = '../src/__generated__';
const OUTPUT_FILE = 'opencti-manifest.json';

const getConnectorManifest = async () => {
  console.info('📝 Getting connectors manifest');
  const schemaUrl = getSchemaURL();
  try {
    // fetch file
    console.info(`➡️ Fetching manifest from: ${schemaUrl}`);
    const data = await fetchManifest(schemaUrl);

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
    console.error(`❌ Error: ${err instanceof Error ? err.message : String(err)}`, err);
    console.error(err);
    process.exit(1);
  }
};

await getConnectorManifest();
