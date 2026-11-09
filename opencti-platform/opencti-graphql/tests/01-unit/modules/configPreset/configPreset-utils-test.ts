import { describe, expect, it } from 'vitest';
import { PLATFORM_VERSION } from '../../../../src/config/conf';
import {
  buildConfigPresetExportMessage,
  buildConfigPresetFileName,
  buildConfigPresetImportMessage,
  sanitizeBundleName,
} from '../../../../src/modules/configPreset/configPreset-utils';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import {
  checkConfigPresetItemModes,
  configPresetImportMode,
  configPresetImportModes,
  findConfigPresetFamily,
  getConfigPresetFamilyModes,
  pickConfigPresetTypeItems,
} from '../../../../src/modules/configPreset/import/configPreset-import-utils';
import type { ConfigPresetBundle } from '../../../../src/modules/configPreset/import/configPreset-import-types';

describe('Config preset naming', () => {
  it('sanitizes the bundle name', () => {
    expect(sanitizeBundleName(undefined)).toBeNull();
    expect(sanitizeBundleName('   ')).toBeNull();
    expect(sanitizeBundleName('<script>alert(1)</script>')).toBe('scriptalert(1)script');
    expect(sanitizeBundleName('Prod\n\tbundle‮  2026')).toBe('Prodbundle 2026');
    expect(sanitizeBundleName('Préréglage SOC_v1.2-(EU)')).toBe('Préréglage SOC_v1.2-(EU)');
    expect(sanitizeBundleName('a'.repeat(100))).toHaveLength(80);
  });

  it('keeps the combining marks and joiners of non-Latin scripts', () => {
    // Hindi: virama and vowel signs are combining marks
    expect(sanitizeBundleName('नमस्ते दुनिया')).toBe('नमस्ते दुनिया');
    // Persian: the zero-width non-joiner is part of the word
    expect(sanitizeBundleName('می‌خواهم')).toBe('می‌خواهم');
    // A decomposed accent is composed
    expect(sanitizeBundleName('Pre\u0301re\u0301glage')).toBe('Pr\u00e9r\u00e9glage');
  });

  it('cuts the bundle name at 80 characters without splitting a character or leaving a space', () => {
    const astral = '\u{1D49C}';
    expect(sanitizeBundleName(`${'a'.repeat(79)}${astral}bc`)).toBe(`${'a'.repeat(79)}${astral}`);
    expect(sanitizeBundleName(`${'a'.repeat(79)} bc`)).toBe('a'.repeat(79));
  });

  it('puts the UTC date, time and platform version in the zip name', () => {
    expect(buildConfigPresetFileName(new Date('2026-01-02T23:59:58.999Z'))).toBe(`opencti-config-20260102-235958-${PLATFORM_VERSION}.zip`);
  });

  it('keeps the zip name in UTC whatever the time zone of the platform', () => {
    const previousTimeZone = process.env.TZ;
    process.env.TZ = 'Pacific/Kiritimati';
    try {
      const date = new Date('2026-01-02T23:59:58.999Z');
      // UTC+14: the local day is already the next one
      expect(date.getDate()).toBe(3);
      expect(buildConfigPresetFileName(date)).toBe(`opencti-config-20260102-235958-${PLATFORM_VERSION}.zip`);
    } finally {
      if (previousTimeZone === undefined) {
        delete process.env.TZ;
      } else {
        process.env.TZ = previousTimeZone;
      }
    }
  });
});

describe('Config preset export activity message', () => {
  it('names the file and the number of items exported per type', () => {
    const message = buildConfigPresetExportMessage({
      path: 'config_preset/0b5c1e9e-4b0a-4f37-9a43-1f1c2b7c9d10',
      file_name: 'opencti-config-20261014-090507-7.0.0.zip',
      input: {
        entity_types: ['platform', 'messages'],
        counts: { platform: 1, messages: 2 },
        items: { platform: ['platform'], messages: ['banner', 'login'] },
      },
    });
    expect(message).toBe('exports the configuration preset `opencti-config-20261014-090507-7.0.0.zip` (platform: 1, messages: 2)');
  });
});

describe('Config preset import activity message', () => {
  it('gives the report and the number of items per result', () => {
    const message = buildConfigPresetImportMessage({
      file_id: 'config_preset/history/id/import-report.json',
      path: 'config_preset/history/id',
      file_name: 'import-report.json',
      input: { counts: { created: 1, overwritten: 2, skipped: 3, failed: 4 } },
    });
    expect(message).toEqual('imports a configuration preset (created: 1, overwritten: 2, skipped: 3, failed: 4), report `import-report.json`');
  });

  it('names the type and the bundle of a partial import, which writes no report', () => {
    const message = buildConfigPresetImportMessage({
      file_id: null,
      path: '',
      file_name: 'bundle.zip',
      input: { type: 'branding', counts: { created: 2, overwritten: 0, skipped: 1, failed: 0 } },
    });
    expect(message).toEqual('imports the `branding` items of the configuration bundle `bundle.zip` (created: 2, overwritten: 0, skipped: 1, failed: 0)');
  });

  it('says so when the report could not be written', () => {
    const message = buildConfigPresetImportMessage({
      file_id: null,
      path: 'config_preset/history/id',
      file_name: 'import-report.json',
      input: { counts: { created: 1, overwritten: 0, skipped: 0, failed: 0 } },
    });
    expect(message).toEqual('imports a configuration preset (created: 1, overwritten: 0, skipped: 0, failed: 0), the report could not be written');
  });
});

describe('Config preset import modes', () => {
  it('takes the mode of each item of the selections, OVERWRITE for an item without one', () => {
    const modes = configPresetImportModes([
      { type: 'branding', item_modes: [{ key: 'theme-1', mode: ConfigImportMode.Copy }, { key: 'theme-2', mode: ConfigImportMode.Overwrite }] },
      { type: 'messages', item_modes: null },
      { type: 'platform' },
    ]);
    expect(configPresetImportMode(modes, 'branding', 'theme-1')).toBe(ConfigImportMode.Copy);
    expect(configPresetImportMode(modes, 'branding', 'theme-2')).toBe(ConfigImportMode.Overwrite);
    expect(configPresetImportMode(modes, 'branding', 'theme-3')).toBe(ConfigImportMode.Overwrite);
    expect(configPresetImportMode(modes, 'messages', 'banner')).toBe(ConfigImportMode.Overwrite);
    expect(configPresetImportMode(modes, 'platform', 'platform')).toBe(ConfigImportMode.Overwrite);
  });

  it('does not take the mode of an item for the item of another type with the same key', () => {
    const modes = configPresetImportModes([{ type: 'branding', item_modes: [{ key: 'same', mode: ConfigImportMode.Copy }] }]);
    expect(configPresetImportMode(modes, 'messages', 'same')).toBe(ConfigImportMode.Overwrite);
  });

  it('takes the given default mode for an item without one (a partial import copies)', () => {
    const modes = configPresetImportModes([{ type: 'branding', item_modes: [{ key: 'theme-1', mode: ConfigImportMode.Overwrite }] }]);
    expect(configPresetImportMode(modes, 'branding', 'theme-1', ConfigImportMode.Copy)).toBe(ConfigImportMode.Overwrite);
    expect(configPresetImportMode(modes, 'branding', 'theme-2', ConfigImportMode.Copy)).toBe(ConfigImportMode.Copy);
  });

  it('offers the modes of the family, OVERWRITE only when it has none, and refuses another one', () => {
    expect(getConfigPresetFamilyModes(findConfigPresetFamily('branding'))).toEqual([ConfigImportMode.Overwrite, ConfigImportMode.Copy]);
    expect(getConfigPresetFamilyModes(findConfigPresetFamily('messages'))).toEqual([ConfigImportMode.Overwrite]);
    expect(() => checkConfigPresetItemModes(findConfigPresetFamily('branding'), [{ key: 'theme-1', mode: ConfigImportMode.Copy }])).not.toThrow();
    expect(() => checkConfigPresetItemModes(findConfigPresetFamily('messages'), [{ key: 'banner', mode: ConfigImportMode.Copy }]))
      .toThrow('Unsupported import mode for this configuration preset type');
    expect(() => checkConfigPresetItemModes(findConfigPresetFamily('messages'), null)).not.toThrow();
  });

  it('refuses an unknown type', () => {
    expect(() => findConfigPresetFamily('unknown')).toThrow('Unknown configuration preset type');
  });
});

describe('Config preset items of a type', () => {
  const bundle = {
    metadata: { openCTI_version: '7.0.0', generated_at: '', bundle_name: null },
    items: [
      { type: 'branding', id: 'a', path: 'a.json', configuration: {} },
      { type: 'branding', id: 'b', path: 'b.json', configuration: {} },
      { type: 'messages', id: 'banner', path: 'banner.json', configuration: {} },
    ],
    dependencies: {},
    ignored: [],
  } as ConfigPresetBundle;
  const ids = (items: { id: string }[]) => items.map(({ id }) => id);

  it('takes the given items of the type, in the given order', () => {
    expect(ids(pickConfigPresetTypeItems(bundle, 'branding', ['b', 'a']))).toEqual(['b', 'a']);
    expect(pickConfigPresetTypeItems(bundle, 'branding', [])).toEqual([]);
  });

  it('takes every item of the type but the excluded ones when no item is given, and ignores an unknown excluded one', () => {
    expect(ids(pickConfigPresetTypeItems(bundle, 'branding', null))).toEqual(['a', 'b']);
    expect(ids(pickConfigPresetTypeItems(bundle, 'branding', undefined, ['a', 'stale']))).toEqual(['b']);
  });

  it('refuses an item that is not one of the type in the bundle', () => {
    expect(() => pickConfigPresetTypeItems(bundle, 'branding', ['banner'])).toThrow('Unknown configuration preset item');
  });
});
