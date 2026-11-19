import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const CONNECTORS_RAW_URL = 'https://raw.githubusercontent.com/OpenCTI-Platform/connectors';
const branchManifestUrl = (branch: string) => `${CONNECTORS_RAW_URL}/refs/heads/${branch}/manifest.json`;
const tagManifestUrl = (tag: string) => `${CONNECTORS_RAW_URL}/refs/tags/${tag}/manifest.json`;
const MASTER_MANIFEST_URL = branchManifestUrl('master');

// --lts: rolling builds of an LTS branch use the manifest of the last LTS release (package.json version)
// instead of the master one, so that xtm-composer deploys LTS connectors.
const IS_LTS = process.argv.includes('--lts');

const getPackageVersion = (): string => {
  const packageJsonPath = fileURLToPath(new URL('../package.json', import.meta.url));
  return JSON.parse(fs.readFileSync(packageJsonPath, 'utf8')).version;
};

// An LTS line is maintained on a `lts/<release>` branch in both the platform and connectors repositories,
// with versions `<release>`, then `<release>-lts.<n>` (formerly `<release>-lts<n>`).
const getLtsBranch = (version: string): string => `lts/${version.replace(/-lts\.?\d+$/, '')}`;

interface ManifestSource {
  url: string;
  // URL to use instead when `url` does not exist (HTTP 404)
  fallbackUrl?: string;
}

const getManifestSource = (): ManifestSource => {
  if (process.env.OPENCTI_MANIFEST_URL) {
    return { url: process.env.OPENCTI_MANIFEST_URL };
  }
  // use tags instead of master if env from CI TAG is set
  if (process.env.TAG_VERSION) {
    return { url: tagManifestUrl(process.env.TAG_VERSION) };
  }
  if (IS_LTS) {
    // The connectors tag may not exist yet (version bumped during a release, before the connectors tag):
    // fall back to the connectors LTS branch, never to master, whose connectors may not support this LTS
    const version = getPackageVersion();
    return { url: tagManifestUrl(version), fallbackUrl: branchManifestUrl(getLtsBranch(version)) };
  }
  // rolling
  return { url: MASTER_MANIFEST_URL };
};

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
// those, fail at once on any other HTTP error. Returns null when `url` does not exist (HTTP 404).
const fetchWithRetry = async (url: string): Promise<string | null> => {
  let lastError: unknown;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt += 1) {
    try {
      const res = await fetch(url, { headers: getFetchHeaders() });
      if (res.ok) return await res.text();
      if (res.status === 404) return null;
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

const fetchManifest = async ({ url, fallbackUrl }: ManifestSource): Promise<string> => {
  console.info(`➡️ Fetching manifest from: ${url}`);
  const data = await fetchWithRetry(url);
  if (data !== null) return data;
  if (!fallbackUrl) throw new Error('HTTP 404');
  console.warn(`⚠️ Manifest not found (HTTP 404) at ${url}, falling back to: ${fallbackUrl}`);
  return fetchManifest({ url: fallbackUrl });
};

const OUTPUT_DIR = '../src/__generated__';
const OUTPUT_FILE = 'opencti-manifest.json';

const getConnectorManifest = async () => {
  console.info('📝 Getting connectors manifest');
  try {
    // fetch file
    const data = await fetchManifest(getManifestSource());

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
