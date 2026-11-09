import { Readable } from 'node:stream';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../../src/modules/configPreset/import/configPreset-import-lock', () => ({ withConfigPresetImportLock: vi.fn() }));

import { FunctionalError } from '../../../../../src/config/errors';
import { ConfigImportMode } from '../../../../../src/modules/configImport/configImport-types';
import { CONFIG_PRESET_FAMILIES } from '../../../../../src/modules/configPreset/configPreset-registry';
import type { ConfigPresetBundle } from '../../../../../src/modules/configPreset/import/configPreset-import-types';
import { withConfigPresetImportLock } from '../../../../../src/modules/configPreset/import/configPreset-import-lock';
import {
  configPresetPartialImport,
  configPresetPartialImportPreview,
  getConfigPresetPartialImportDefaultMode,
  resolveConfigPresetPartialImportItems,
  resolveConfigPresetPartialImportModes,
} from '../../../../../src/modules/configPreset/import/configPreset-partial-import';
import { configPresetImportMode } from '../../../../../src/modules/configPreset/import/configPreset-import-utils';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';
import { BYPASS } from '../../../../../src/utils/access';

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
    expect(getConfigPresetPartialImportDefaultMode(family('branding'))).toBe(ConfigImportMode.Copy);
    expect(getConfigPresetPartialImportDefaultMode(family('platform'))).toBe(ConfigImportMode.Overwrite);
  });

  it('takes every item of the type, and never the items of another type', () => {
    expect(resolveConfigPresetPartialImportItems(bundle, family('branding'), null).map(({ id }) => id)).toEqual([THEME_A, THEME_B, THEME_C]);
    // The theme the platform item depends on is not imported with it
    expect(resolveConfigPresetPartialImportItems(bundle, family('platform'), null).map(({ id }) => id)).toEqual(['platform']);
  });

  it('takes the selected items and the items of the same type they depend on, dependencies first', () => {
    expect(resolveConfigPresetPartialImportItems(bundle, family('branding'), [THEME_C]).map(({ id }) => id)).toEqual([THEME_B, THEME_C]);
    expect(resolveConfigPresetPartialImportItems(bundle, family('branding'), [])).toEqual([]);
  });

  it('refuses an item that is not in the bundle for the type', () => {
    expect(() => resolveConfigPresetPartialImportItems(bundle, family('branding'), ['platform'])).toThrow('Unknown configuration preset item');
  });

  it('gives each item its mode, the default one of the partial import when none is given, and refuses a mode the type does not offer', () => {
    const modes = resolveConfigPresetPartialImportModes(family('branding'), [{ key: THEME_B, mode: ConfigImportMode.Overwrite }]);
    const defaultMode = getConfigPresetPartialImportDefaultMode(family('branding'));
    expect(configPresetImportMode(modes, 'branding', THEME_A, defaultMode)).toBe(ConfigImportMode.Copy);
    expect(configPresetImportMode(modes, 'branding', THEME_B, defaultMode)).toBe(ConfigImportMode.Overwrite);
    expect(() => resolveConfigPresetPartialImportModes(family('branding'), [{ key: THEME_A, mode: ConfigImportMode.Add }]))
      .toThrow('Unsupported import mode for this configuration preset type');
  });
});

describe('Config preset partial import: lock', () => {
  const context = { source: 'test' } as AuthContext;
  const bypassUser = { id: 'user-id', capabilities: [{ name: BYPASS }] } as unknown as AuthUser;
  // An upload that records when it is read: not a zip, so a read is refused as a bundle
  const trackedUpload = (calls: string[]) => {
    const createReadStream = vi.fn(() => {
      calls.push('read');
      return Readable.from([Buffer.from('not a zip')]);
    });
    return { file: Promise.resolve({ createReadStream, filename: 'bundle.zip' }), createReadStream };
  };

  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('refuses a second import at once, without reading its zip', async () => {
    vi.mocked(withConfigPresetImportLock).mockRejectedValue(FunctionalError('An import is already running', { reason: 'import_running' }));
    const { file, createReadStream } = trackedUpload([]);
    await expect(configPresetPartialImport(context, bypassUser, file, 'branding', ['theme--a'], [])).rejects.toThrow('An import is already running');
    expect(createReadStream).not.toHaveBeenCalled();
  });

  it('takes the lock before it reads the zip', async () => {
    const calls: string[] = [];
    vi.mocked(withConfigPresetImportLock).mockImplementation(async (_context, fn) => {
      calls.push('lock');
      return fn({ signal: new AbortController().signal } as never);
    });
    const { file } = trackedUpload(calls);
    await expect(configPresetPartialImport(context, bypassUser, file, 'branding', ['theme--a'], [])).rejects.toThrow('The file is not a valid zip archive');
    expect(calls).toEqual(['lock', 'read']);
  });

  it('checks the access and the type before the lock', async () => {
    const { file } = trackedUpload([]);
    const editor = { id: 'user-id', capabilities: [{ name: 'KNOWLEDGE' }] } as unknown as AuthUser;
    await expect(configPresetPartialImport(context, editor, file, 'branding', ['theme--a'], [])).rejects.toThrow();
    await expect(configPresetPartialImport(context, bypassUser, file, 'unknown', ['theme--a'], [])).rejects.toThrow('Unknown configuration preset type');
    expect(withConfigPresetImportLock).not.toHaveBeenCalled();
  });

  it('previews without the lock: it writes nothing and works while an import runs', async () => {
    const { file, createReadStream } = trackedUpload([]);
    await expect(configPresetPartialImportPreview(context, bypassUser, file, 'branding')).rejects.toThrow('The file is not a valid zip archive');
    expect(createReadStream).toHaveBeenCalled();
    expect(withConfigPresetImportLock).not.toHaveBeenCalled();
  });
});
