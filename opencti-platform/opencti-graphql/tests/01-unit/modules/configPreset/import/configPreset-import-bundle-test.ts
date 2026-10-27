import { describe, expect, it } from 'vitest';
import {
  CONFIG_PRESET_IMPORT_MAX_ENTRIES,
  CONFIG_PRESET_IMPORT_MAX_ENTRY_SIZE,
  readConfigPresetBundle,
  resolveBundleDependencies,
} from '../../../../../src/modules/configPreset/import/configPreset-import-bundle';
import { buildZip, CUSTOM_THEME_ID, itemFile, metadataFile, OTHER_THEME_ID, themeConfiguration, validBundleFiles } from '../../../../utils/configPresetBundle';

const refusedWith = async (zip: Buffer | Promise<Buffer>) => {
  const error = await readConfigPresetBundle(await zip).catch((err) => err);
  expect(error.extensions?.data?.reason).toEqual('bundle_refused');
  return error;
};

describe('Config preset bundle reader', () => {
  it('reads the metadata and matches each item to its family by its type, not by its path', async () => {
    const files = { ...validBundleFiles(), 'somewhere/else/banner-renamed.json': itemFile('platformSettings.messages', 'login', { platform_login_message: 'Hi' }) };
    const bundle = await readConfigPresetBundle(await buildZip(files));
    expect(bundle.metadata).toEqual({ openCTI_version: expect.any(String), generated_at: '2026-10-20T10:00:00.000Z', bundle_name: 'Test bundle' });
    expect(bundle.items.map(({ type, id }) => `${type}/${id}`).sort()).toEqual([
      `branding/${CUSTOM_THEME_ID}`, 'branding/whitemark', 'messages/banner', 'messages/login', 'platform/platform',
    ]);
    expect(bundle.items.find((item) => item.id === 'login')?.path).toEqual('somewhere/else/banner-renamed.json');
    expect(bundle.ignored).toEqual([]);
  });

  it('ignores and reports an unknown type, an unknown file and a family without importer', async () => {
    const files = {
      ...validBundleFiles(),
      'other/unknown.json': itemFile('platformSettings.unknown', 'x', {}),
      'other/not-an-item.json': JSON.stringify({ hello: 'world' }),
      'README.txt': 'hello',
      'data_model/hidden_entity_types.json': itemFile('dataModel.hiddenEntityTypes', 'hiddenEntityTypes', { hidden_entity_types: [] }),
    };
    const bundle = await readConfigPresetBundle(await buildZip(files));
    expect(bundle.items).toHaveLength(4);
    expect(bundle.ignored.sort()).toEqual(['README.txt', 'data_model/hidden_entity_types.json', 'other/not-an-item.json', 'other/unknown.json']);
  });

  it('accepts the same version with a -dev suffix and an older version', async () => {
    expect((await readConfigPresetBundle(await buildZip({ ...validBundleFiles(), 'metadata.json': metadataFile('0.0.1-dev') }))).items).toHaveLength(4);
    expect((await readConfigPresetBundle(await buildZip({ ...validBundleFiles(), 'metadata.json': metadataFile('1.0.0') }))).items).toHaveLength(4);
  });

  it('refuses a bundle from a more recent platform and an unreadable version, without a TypeError', async () => {
    const recent = await refusedWith(buildZip({ ...validBundleFiles(), 'metadata.json': metadataFile('999.0.0') }));
    expect(recent.message).toContain('more recent');
    await refusedWith(buildZip({ ...validBundleFiles(), 'metadata.json': metadataFile('not-a-version') }));
  });

  it('refuses a file that is not a zip, a zip without metadata and invalid JSON', async () => {
    await refusedWith(Buffer.from('this is not a zip'));
    const { 'metadata.json': _metadata, ...withoutMetadata } = validBundleFiles();
    await refusedWith(buildZip(withoutMetadata));
    await refusedWith(buildZip({ ...validBundleFiles(), 'platform_settings/broken.json': '{ not json' }));
    await refusedWith(buildZip({ ...validBundleFiles(), 'metadata.json': JSON.stringify({ generated_at: 'x' }) }));
  });

  it('refuses an entry above the size limit, whatever the size declared', async () => {
    const big = JSON.stringify({ padding: 'a'.repeat(CONFIG_PRESET_IMPORT_MAX_ENTRY_SIZE + 1) });
    await refusedWith(buildZip({ ...validBundleFiles(), 'platform_settings/big.json': big }));
  });

  it('refuses too many entries and the same item twice', async () => {
    const many = Object.fromEntries(Array.from({ length: CONFIG_PRESET_IMPORT_MAX_ENTRIES + 1 }, (_, i) => [`f${i}.txt`, 'x']));
    await refusedWith(buildZip(many));
    await refusedWith(buildZip({
      ...validBundleFiles(),
      'copy/banner.json': itemFile('platformSettings.messages', 'banner', { platform_banner_text: 'Other' }),
    }));
  });
});

describe('Config preset bundle dependencies', () => {
  it('adds the dependencies of the selection first, from dependencies.json', async () => {
    const bundle = await readConfigPresetBundle(await buildZip(validBundleFiles()));
    const ordered = resolveBundleDependencies(bundle, [{ type: 'platform', id: 'platform' }]);
    expect(ordered.map(({ type, id }) => `${type}/${id}`)).toEqual([`branding/${CUSTOM_THEME_ID}`, 'platform/platform']);
  });

  it('follows the file of a dependency whatever its type, and survives a cycle or a missing file', async () => {
    const files = {
      ...validBundleFiles(),
      [`platform_settings/branding/${OTHER_THEME_ID}.json`]: itemFile('platformSettings.branding', OTHER_THEME_ID, themeConfiguration({ standard_id: OTHER_THEME_ID, name: 'Other' })),
      'dependencies.json': JSON.stringify({
        'platformSettings.platform': { platform: { [CUSTOM_THEME_ID]: `platform_settings/branding/${CUSTOM_THEME_ID}.json`, missing: 'nowhere.json' } },
        'platformSettings.branding': { [CUSTOM_THEME_ID]: { [OTHER_THEME_ID]: `platform_settings/branding/${OTHER_THEME_ID}.json` }, [OTHER_THEME_ID]: { platform: 'platform_settings/platform.json' } },
      }),
    };
    const bundle = await readConfigPresetBundle(await buildZip(files));
    const ordered = resolveBundleDependencies(bundle, [{ type: 'platform', id: 'platform' }]);
    expect(ordered.map(({ id }) => id)).toEqual([OTHER_THEME_ID, CUSTOM_THEME_ID, 'platform']);
  });

  it('does not add anything for an item without dependency', async () => {
    const bundle = await readConfigPresetBundle(await buildZip(validBundleFiles()));
    expect(resolveBundleDependencies(bundle, [{ type: 'messages', id: 'banner' }]).map(({ id }) => id)).toEqual(['banner']);
  });
});
