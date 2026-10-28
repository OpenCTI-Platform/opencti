import { ZipArchive } from 'archiver';
import { PLATFORM_VERSION } from '../../src/config/conf';

export const CUSTOM_THEME_ID = 'theme--11111111-2222-4333-8444-555555555555';
export const OTHER_THEME_ID = 'theme--aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';

// A zip in memory from a map of path -> content
export const buildZip = async (files: Record<string, string | Buffer>): Promise<Buffer> => {
  const archive = new ZipArchive();
  const chunks: Buffer[] = [];
  archive.on('data', (chunk: Buffer) => chunks.push(chunk));
  const done = new Promise<void>((resolve, reject) => {
    archive.on('end', resolve);
    archive.on('error', reject);
  });
  Object.entries(files).forEach(([name, content]) => archive.append(content, { name }));
  await Promise.all([archive.finalize(), done]);
  return Buffer.concat(chunks);
};

export const metadataFile = (version: string = PLATFORM_VERSION, bundleName: string | null = 'Test bundle') => {
  return JSON.stringify({ openCTI_version: version, generated_at: '2026-10-20T10:00:00.000Z', bundle_name: bundleName });
};

export const itemFile = (type: string, id: string, configuration: Record<string, unknown>, version: string = PLATFORM_VERSION) => {
  return JSON.stringify({ openCTI_version: version, type, id, configuration });
};

export const themeConfiguration = (overrides: Record<string, unknown> = {}) => ({
  standard_id: CUSTOM_THEME_ID,
  name: 'Import test theme',
  theme_background: '#101010',
  theme_paper: '#202020',
  theme_nav: '#303030',
  theme_primary: '#ff0000',
  theme_secondary: '#00ff00',
  theme_accent: '#0000ff',
  theme_text_color: '#ffffff',
  theme_logo: 'https://example.com/logo.png',
  ...overrides,
});

// A bundle with a platform item depending on a custom default theme, a message and the whitemark
export const validBundleFiles = (): Record<string, string> => ({
  'metadata.json': metadataFile(),
  'dependencies.json': JSON.stringify({
    'platformSettings.platform': { platform: { [CUSTOM_THEME_ID]: `platform_settings/branding/${CUSTOM_THEME_ID}.json` } },
  }),
  'platform_settings/platform.json': itemFile('platformSettings.platform', 'platform', {
    platform_title: 'Imported title',
    platform_favicon: 'https://example.com/favicon.ico',
    platform_language: 'fr-fr',
    default_theme: { standard_id: CUSTOM_THEME_ID, name: 'Import test theme' },
  }),
  [`platform_settings/branding/${CUSTOM_THEME_ID}.json`]: itemFile('platformSettings.branding', CUSTOM_THEME_ID, themeConfiguration()),
  'platform_settings/branding/whitemark.json': itemFile('platformSettings.branding', 'whitemark', { platform_whitemark: true }),
  'platform_settings/messages/banner.json': itemFile('platformSettings.messages', 'banner', { platform_banner_text: 'Hello', platform_banner_level: 'GREEN' }),
});
