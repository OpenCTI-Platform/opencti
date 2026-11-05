import { describe, expect, it } from 'vitest';
import { ConfigImportMode } from '../../../../../src/modules/configImport/configImport-types';
import { CONFIG_PRESET_FAMILIES } from '../../../../../src/modules/configPreset/configPreset-registry';
import type { ConfigPresetBundle } from '../../../../../src/modules/configPreset/import/configPreset-import-types';
import {
  configPresetPartialImportDefaultMode,
  configPresetPartialImportModes,
  resolveConfigPresetPartialItems,
} from '../../../../../src/modules/configPreset/import/configPreset-partial-import';

const family = (id: string) => CONFIG_PRESET_FAMILIES.find((candidate) => candidate.id === id)!;
const THEME_A = 'theme--11111111-2222-4333-8444-555555555555';
const THEME_B = 'theme--aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const THEME_C = 'theme--cccccccc-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const themePath = (id: string) => `platform_settings/branding/${id}.json`;

// A platform item depending on THEME_A, THEME_C depending on THEME_B (a dependency of the same type)
const bundle: ConfigPresetBundle = {
  metadata: { openCTI_version: '7.0.0', generated_at: '2026-10-20T10:00:00.000Z', bundle_name: 'Test' },
  items: [
    { type: 'platform', id: 'platform', path: 'platform_settings/platform.json', configuration: {} },
    { type: 'branding', id: THEME_A, path: themePath(THEME_A), configuration: {} },
    { type: 'branding', id: THEME_B, path: themePath(THEME_B), configuration: {} },
    { type: 'branding', id: THEME_C, path: themePath(THEME_C), configuration: {} },
  ],
  dependencies: {
    'platformSettings.platform': { platform: { [THEME_A]: themePath(THEME_A) } },
    'platformSettings.branding': { [THEME_C]: { [THEME_B]: themePath(THEME_B) } },
  },
  ignored: [],
};

describe('Config preset partial import', () => {
  it('adds as a copy by default when the type offers it, else takes the default of the type', () => {
    expect(configPresetPartialImportDefaultMode(family('branding'))).toBe(ConfigImportMode.Copy);
    expect(configPresetPartialImportDefaultMode(family('platform'))).toBe(ConfigImportMode.Overwrite);
  });

  it('takes every item of the type, and never the items of another type', () => {
    expect(resolveConfigPresetPartialItems(bundle, family('branding'), null).map(({ id }) => id)).toEqual([THEME_A, THEME_B, THEME_C]);
    // The theme the platform item depends on is not imported with it
    expect(resolveConfigPresetPartialItems(bundle, family('platform'), null).map(({ id }) => id)).toEqual(['platform']);
  });

  it('takes the selected items and the items of the same type they depend on, dependencies first', () => {
    expect(resolveConfigPresetPartialItems(bundle, family('branding'), [THEME_C]).map(({ id }) => id)).toEqual([THEME_B, THEME_C]);
    expect(resolveConfigPresetPartialItems(bundle, family('branding'), [])).toEqual([]);
  });

  it('refuses an item that is not in the bundle for the type', () => {
    expect(() => resolveConfigPresetPartialItems(bundle, family('branding'), ['platform'])).toThrow('Unknown configuration preset item');
  });

  it('gives each item its mode, the default one when none is given, and refuses a mode the type does not offer', () => {
    const items = resolveConfigPresetPartialItems(bundle, family('branding'), [THEME_A, THEME_B]);
    const modes = configPresetPartialImportModes(family('branding'), items, [{ key: THEME_B, mode: ConfigImportMode.Overwrite }]);
    expect(Object.fromEntries(modes)).toEqual({ [`branding/${THEME_A}`]: ConfigImportMode.Copy, [`branding/${THEME_B}`]: ConfigImportMode.Overwrite });
    expect(() => configPresetPartialImportModes(family('branding'), items, [{ key: THEME_A, mode: ConfigImportMode.Add }]))
      .toThrow('Unsupported import mode for this configuration preset type');
  });
});
