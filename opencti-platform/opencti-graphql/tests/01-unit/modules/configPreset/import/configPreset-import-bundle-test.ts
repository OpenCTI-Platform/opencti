import { Readable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { CONFIG_PRESET_FAMILIES } from '../../../../../src/modules/configPreset/configPreset-registry';
import {
  CONFIG_PRESET_IMPORT_MAX_ENTRY_SIZE,
  CONFIG_PRESET_IMPORT_MAX_TOTAL_SIZE,
  limitStream,
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
      `branding/${CUSTOM_THEME_ID}`, 'messages/banner', 'messages/login', 'platform/platform',
    ]);
    expect(bundle.items.find((item) => item.id === 'login')?.path).toEqual('somewhere/else/banner-renamed.json');
    expect(bundle.ignored).toEqual([]);
  });

  it('ignores and reports an unknown type and an unknown file', async () => {
    const files = {
      ...validBundleFiles(),
      'other/unknown.json': itemFile('platformSettings.unknown', 'x', {}),
      'other/not-an-item.json': JSON.stringify({ hello: 'world' }),
      'README.txt': 'hello',
    };
    const bundle = await readConfigPresetBundle(await buildZip(files));
    expect(bundle.items).toHaveLength(3);
    expect(bundle.ignored.sort()).toEqual(['README.txt', 'other/not-an-item.json', 'other/unknown.json']);
  });

  describe('the attachment of an item', () => {
    const ID = '3f1d0c4e-7a52-4b8e-9f3a-1c2d3e4f5a6b';
    const JSON_PATH = `customization/exclusion_lists/${ID}.json`;
    const TXT_PATH = `customization/exclusion_lists/${ID}.txt`;
    // The JSON of an item of the family, pointing to a file (or to none)
    const withAttachment = (attachment: string | undefined, id = ID, path = JSON_PATH) => ({
      [path]: JSON.stringify({
        openCTI_version: '0.0.1',
        type: 'customization.exclusionLists',
        id,
        configuration: { name: 'DNS', exclusion_list_entity_types: ['IPv4-Addr'] },
        ...(attachment ? { attachment } : {}),
      }),
    });
    const read = async (files: Record<string, string | Buffer>) => readConfigPresetBundle(await buildZip({ 'metadata.json': metadataFile(), ...files }));

    it('is the entry of the zip its JSON points to, read when it is asked for, and is not reported as ignored', async () => {
      const bundle = await read({ ...withAttachment(TXT_PATH), [TXT_PATH]: '8.8.8.8\n1.1.1.1\n' });
      expect(bundle.items).toHaveLength(1);
      expect(bundle.items[0].attachment?.path).toBe(TXT_PATH);
      expect(await bundle.items[0].attachment!.read(1024)).toEqual(Buffer.from('8.8.8.8\n1.1.1.1\n'));
      // Read again: the bundle keeps nothing of it
      expect(await bundle.items[0].attachment!.read(1024)).toEqual(Buffer.from('8.8.8.8\n1.1.1.1\n'));
      expect(bundle.ignored).toEqual([]);
    });

    it('is read byte for byte, whatever its content', async () => {
      const bytes = Buffer.from([0x38, 0x0d, 0x0a, 0xc3, 0xa9, 0xff, 0x00, 0x0a]);
      const bundle = await read({ ...withAttachment(TXT_PATH), [TXT_PATH]: bytes });
      expect(await bundle.items[0].attachment!.read(1024)).toEqual(bytes);
    });

    it('gives null, and nothing else, when it holds more than the limit', async () => {
      const bundle = await read({ ...withAttachment(TXT_PATH), [TXT_PATH]: Buffer.alloc(2048, 'a') });
      expect(await bundle.items[0].attachment!.read(2047)).toBeNull();
      expect(await bundle.items[0].attachment!.read(2048)).toHaveLength(2048);
    });

    it('is not bound by the limit of a JSON file of the bundle', async () => {
      const bundle = await read({ ...withAttachment(TXT_PATH), [TXT_PATH]: Buffer.alloc(CONFIG_PRESET_IMPORT_MAX_ENTRY_SIZE + 1, 'a') });
      expect(await bundle.items[0].attachment!.read(CONFIG_PRESET_IMPORT_MAX_ENTRY_SIZE + 1)).toHaveLength(CONFIG_PRESET_IMPORT_MAX_ENTRY_SIZE + 1);
    });

    it('counts against the extracted size limit of the bundle, with the JSON files', async () => {
      const size = CONFIG_PRESET_IMPORT_MAX_ENTRY_SIZE;
      const count = Math.floor(CONFIG_PRESET_IMPORT_MAX_TOTAL_SIZE / size) + 1;
      const files: Record<string, string | Buffer> = {};
      for (let i = 0; i < count; i += 1) {
        const id = `aaaaaaaa-bbbb-4ccc-8ddd-${String(i).padStart(12, '0')}`;
        const txt = `customization/exclusion_lists/${id}.txt`;
        Object.assign(files, withAttachment(txt, id, `customization/exclusion_lists/${id}.json`), { [txt]: Buffer.alloc(size, 'a') });
      }
      const bundle = await read(files);
      expect(bundle.items).toHaveLength(count);
      const error = await (async () => {
        for (const item of bundle.items) {
          await item.attachment!.read(size);
        }
      })().catch((err) => err);
      expect(error.extensions?.data?.reason).toEqual('bundle_refused');
      expect(error.message).toContain('too large once extracted');
    });

    it('is absent when the zip has no entry at the path, and an item without attachment has none', async () => {
      const missing = await read(withAttachment(TXT_PATH));
      expect(missing.items[0].attachment).toBeUndefined();
      const none = await read(withAttachment(undefined));
      expect(none.items[0].attachment).toBeUndefined();
    });

    it('is looked up in the zip only: a path out of it or a path of the disk gives no attachment', async () => {
      const outside = await read({ ...withAttachment('../../etc/passwd'), [TXT_PATH]: 'x' });
      expect(outside.items[0].attachment).toBeUndefined();
      expect(outside.ignored).toEqual([TXT_PATH]);
    });

    // The path is compared as it is written: nothing is normalized or resolved, and a JSON entry is never a file
    it.each([`./${TXT_PATH}`, `/${TXT_PATH}`, 'metadata.json', JSON_PATH])('does not resolve the pointer %s', async (pointer) => {
      const bundle = await read({ ...withAttachment(pointer), [TXT_PATH]: 'x' });
      expect(bundle.items.find((item) => item.path === JSON_PATH)?.attachment).toBeUndefined();
      expect(bundle.ignored).toContain(TXT_PATH);
    });

    it('gives an attachment two items point to to the first item of the zip, the other one has none', async () => {
      const second = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
      const secondPath = `customization/exclusion_lists/${second}.json`;
      const bundle = await read({ ...withAttachment(TXT_PATH), ...withAttachment(TXT_PATH, second, secondPath), [TXT_PATH]: 'x' });
      expect(bundle.items.find((item) => item.path === JSON_PATH)?.attachment?.path).toBe(TXT_PATH);
      expect(bundle.items.find((item) => item.path === secondPath)?.attachment).toBeUndefined();
    });

    it('serves one item only, and an entry no item points to is reported as ignored', async () => {
      const second = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
      const bundle = await read({
        ...withAttachment(TXT_PATH),
        ...withAttachment(TXT_PATH, second, `customization/exclusion_lists/${second}.json`),
        [TXT_PATH]: 'x',
        'customization/exclusion_lists/orphan.txt': 'y',
      });
      expect(bundle.items.filter((item) => item.attachment)).toHaveLength(1);
      expect(bundle.ignored).toEqual(['customization/exclusion_lists/orphan.txt']);
    });
  });

  it('reads the hidden entity types as an item of the bundle', async () => {
    const files = { ...validBundleFiles(), 'data_model/hidden_entity_types.json': itemFile('dataModel.hiddenEntityTypes', 'hiddenEntityTypes', { hidden_entity_types: ['Malware'] }) };
    const bundle = await readConfigPresetBundle(await buildZip(files));
    expect(bundle.items).toHaveLength(4);
    expect(bundle.items.find((item) => item.type === 'hiddenEntityTypes')).toMatchObject({ id: 'hiddenEntityTypes', configuration: { hidden_entity_types: ['Malware'] } });
    expect(bundle.ignored).toEqual([]);
  });

  it('reports the items of a family without importer as not importable', async () => {
    const family = CONFIG_PRESET_FAMILIES.find(({ id }) => id === 'hiddenEntityTypes')!;
    const { importer } = family;
    family.importer = undefined;
    try {
      const files = { ...validBundleFiles(), 'data_model/hidden_entity_types.json': itemFile('dataModel.hiddenEntityTypes', 'hiddenEntityTypes', { hidden_entity_types: [] }) };
      const bundle = await readConfigPresetBundle(await buildZip(files));
      expect(bundle.items).toHaveLength(3);
      expect(bundle.ignored).toEqual(['data_model/hidden_entity_types.json']);
    } finally {
      family.importer = importer;
    }
  });

  it('accepts the same version with a -dev suffix and an older version', async () => {
    expect((await readConfigPresetBundle(await buildZip({ ...validBundleFiles(), 'metadata.json': metadataFile('0.0.1-dev') }))).items).toHaveLength(3);
    expect((await readConfigPresetBundle(await buildZip({ ...validBundleFiles(), 'metadata.json': metadataFile('1.0.0') }))).items).toHaveLength(3);
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

  it('refuses a bundle that is too large once extracted, each entry being under the limit', async () => {
    const padding = JSON.stringify({ padding: 'a'.repeat(CONFIG_PRESET_IMPORT_MAX_ENTRY_SIZE - 100) });
    const count = Math.ceil(CONFIG_PRESET_IMPORT_MAX_TOTAL_SIZE / padding.length) + 1;
    const files = Object.fromEntries(Array.from({ length: count }, (_, i) => [`padding/${i}.json`, padding]));
    const error = await refusedWith(buildZip({ ...validBundleFiles(), ...files }));
    expect(error.message).toContain('too large once extracted');
  });

  it('refuses dependencies that are not a map of maps of maps of paths', async () => {
    const error = await refusedWith(buildZip({ ...validBundleFiles(), 'dependencies.json': JSON.stringify({ 'platformSettings.platform': { platform: 'platform_settings/branding/theme.json' } }) }));
    expect(error.message).toContain('dependencies of the configuration bundle are invalid');
  });

  it('refuses the same item twice', async () => {
    await refusedWith(buildZip({
      ...validBundleFiles(),
      'copy/banner.json': itemFile('platformSettings.messages', 'banner', { platform_banner_text: 'Other' }),
    }));
  });
});

describe('Config preset upload limit', () => {
  const chunks = (count: number) => Readable.from(Array.from({ length: count }, () => Buffer.alloc(1024)));

  it('lets a stream under the limit through unchanged', async () => {
    const read: Buffer[] = [];
    for await (const chunk of limitStream(chunks(3), 4096)) {
      read.push(chunk);
    }
    expect(Buffer.concat(read)).toHaveLength(3 * 1024);
  });

  it('refuses a stream over the limit as a refused bundle and destroys the source, so its temporary file is released', async () => {
    const source = chunks(10);
    const error = await (async () => {
      for await (const _chunk of limitStream(source, 4096)) {
        // read until the refusal
      }
    })().catch((err) => err);
    expect(error.message).toEqual('The configuration bundle is too large');
    expect(error.extensions?.data).toMatchObject({ reason: 'bundle_refused', limit: 4096 });
    expect(source.destroyed).toBe(true);
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
