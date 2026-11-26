import { describe, expect, it } from 'vitest';
import { PLATFORM_VERSION } from '../../../../../src/config/conf';
import { CONFIG_PRESET_FAMILIES } from '../../../../../src/modules/configPreset/configPreset-registry';
import type { ConfigPresetFamilyDefinition } from '../../../../../src/modules/configPreset/configPreset-types';
import { readConfigPresetBundle } from '../../../../../src/modules/configPreset/import/configPreset-import-bundle';
import { computeConfigPresetItem } from '../../../../../src/modules/configPreset/import/configPreset-import-domain';
import { CONFIG_PRESET_CODE_INCOMPATIBLE_VERSION, type ConfigPresetBundleItem } from '../../../../../src/modules/configPreset/import/configPreset-import-types';
import { CONFIG_PRESET_MINIMAL_COMPATIBLE_VERSION, getConfigPresetItemIncompatibility } from '../../../../../src/modules/configPreset/import/configPreset-import-version';
import { ConfigImportMode } from '../../../../../src/modules/configImport/configImport-types';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';
import { buildZip, itemFile, metadataFile, validBundleFiles } from '../../../../utils/configPresetBundle';

const messagesFamily = CONFIG_PRESET_FAMILIES.find(({ id }) => id === 'messages')!;
const platformFamily = CONFIG_PRESET_FAMILIES.find(({ id }) => id === 'platform')!;

describe('Config preset item version compatibility', () => {
  it('accepts the version of the platform, with or without a suffix, and the minimal version', () => {
    expect(getConfigPresetItemIncompatibility(messagesFamily, PLATFORM_VERSION)).toBeNull();
    expect(getConfigPresetItemIncompatibility(messagesFamily, `${PLATFORM_VERSION}-dev`)).toBeNull();
    expect(getConfigPresetItemIncompatibility(messagesFamily, CONFIG_PRESET_MINIMAL_COMPATIBLE_VERSION)).toBeNull();
    expect(getConfigPresetItemIncompatibility(messagesFamily, undefined)).toBeNull();
  });

  it('refuses an item from a more recent platform', () => {
    expect(getConfigPresetItemIncompatibility(messagesFamily, '999.0.0')).toEqual('Exported from a more recent platform: 999.0.0');
  });

  it('refuses an item older than the minimal version of its family', () => {
    expect(getConfigPresetItemIncompatibility(messagesFamily, '6.0.0'))
      .toEqual(`Exported from a version that is no longer supported: 6.0.0 (minimum ${CONFIG_PRESET_MINIMAL_COMPATIBLE_VERSION})`);
    const family = { ...messagesFamily, minimalCompatibleVersion: PLATFORM_VERSION } as ConfigPresetFamilyDefinition;
    expect(getConfigPresetItemIncompatibility(family, CONFIG_PRESET_MINIMAL_COMPATIBLE_VERSION))
      .toEqual(`Exported from a version that is no longer supported: ${CONFIG_PRESET_MINIMAL_COMPATIBLE_VERSION} (minimum ${PLATFORM_VERSION})`);
  });

  it('refuses an unreadable version', () => {
    expect(getConfigPresetItemIncompatibility(messagesFamily, 'not-a-version')).toEqual('Unreadable version: not-a-version');
  });

  it('reads the version of each item, the one of the bundle when its file has none', async () => {
    const files = {
      ...validBundleFiles(),
      'platform_settings/messages/banner.json': itemFile('platformSettings.messages', 'banner', { platform_banner_text: 'Hi' }, '6.0.0'),
      'platform_settings/messages/login.json': JSON.stringify({ type: 'platformSettings.messages', id: 'login', configuration: {} }),
      'metadata.json': metadataFile(CONFIG_PRESET_MINIMAL_COMPATIBLE_VERSION),
    };
    const bundle = await readConfigPresetBundle(await buildZip(files));
    expect(bundle.items.find(({ id }) => id === 'banner')?.openCTI_version).toEqual('6.0.0');
    expect(bundle.items.find(({ id }) => id === 'login')?.openCTI_version).toEqual(CONFIG_PRESET_MINIMAL_COMPATIBLE_VERSION);
  });

  it('skips an incompatible item without calling its importer, with the reason and the code', async () => {
    const context = { source: 'test' } as AuthContext;
    const user = { id: 'user-id' } as AuthUser;
    const compute = (family: ConfigPresetFamilyDefinition, item: ConfigPresetBundleItem) => {
      return computeConfigPresetItem(context, user, family, item, { created: new Set() }, ConfigImportMode.Overwrite, true);
    };
    expect(await compute(platformFamily, { type: 'platform', id: 'platform', path: 'p.json', openCTI_version: '999.0.0', configuration: {} })).toEqual({
      label: 'Platform configuration',
      translatable: true,
      exists: false,
      conflict: false,
      status: 'skipped',
      reason: 'Exported from a more recent platform: 999.0.0',
      code: CONFIG_PRESET_CODE_INCOMPATIBLE_VERSION,
    });
    expect(await compute(messagesFamily, { type: 'messages', id: 'banner', path: 'b.json', openCTI_version: '6.0.0', configuration: { name: 'Banner' } }))
      .toMatchObject({ label: 'Banner', translatable: false, status: 'skipped', code: CONFIG_PRESET_CODE_INCOMPATIBLE_VERSION });
  });
});
