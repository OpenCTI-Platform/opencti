import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const CONNECTORS_RAW_URL = 'https://raw.githubusercontent.com/OpenCTI-Platform/connectors';
const MASTER_MANIFEST_URL = `${CONNECTORS_RAW_URL}/refs/heads/master/manifest.json`;
const tagManifestUrl = (tag: string) => `${CONNECTORS_RAW_URL}/refs/tags/${tag}/manifest.json`;

// --lts: rolling builds of an LTS branch use the manifest of the last LTS release (package.json version)
// instead of the master one, so that xtm-composer deploys LTS connectors.
const IS_LTS = process.argv.includes('--lts');

const getPackageVersion = (): string => {
  const packageJsonPath = fileURLToPath(new URL('../package.json', import.meta.url));
  return JSON.parse(fs.readFileSync(packageJsonPath, 'utf8')).version;
};

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
    // The connectors tag may not exist yet (version bumped during a release, before the connectors tag)
    return { url: tagManifestUrl(getPackageVersion()), fallbackUrl: MASTER_MANIFEST_URL };
  }
  // rolling
  return { url: MASTER_MANIFEST_URL };
};

const getFetchHeaders = () => {
  const headersEnv = process.env.OPENCTI_MANIFEST_HEADERS;
  return headersEnv ? JSON.parse(headersEnv) : {};
};

const fetchManifest = async ({ url, fallbackUrl }: ManifestSource): Promise<string> => {
  console.info(`➡️ Fetching manifest from: ${url}`);
  const res = await fetch(url, { headers: getFetchHeaders() });
  if (res.status === 404 && fallbackUrl) {
    console.warn(`⚠️ Manifest not found (HTTP 404) at ${url}, falling back to: ${fallbackUrl}`);
    return fetchManifest({ url: fallbackUrl });
  }
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.text();
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
