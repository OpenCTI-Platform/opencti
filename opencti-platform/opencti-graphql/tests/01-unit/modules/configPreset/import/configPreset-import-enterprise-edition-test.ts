import { beforeEach, describe, expect, it, vi } from 'vitest';

const enterpriseEdition = vi.hoisted(() => ({ enabled: true }));
vi.mock('../../../../../src/enterprise-edition/ee', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/enterprise-edition/ee')>()),
  isEnterpriseEdition: vi.fn(async () => enterpriseEdition.enabled),
}));
vi.mock('../../../../../src/domain/settings', () => ({
  getSettings: vi.fn(),
  settingsEditField: vi.fn(),
  getPlatformDefaultTheme: vi.fn(),
}));

import { CONFIG_PRESET_FAMILIES } from '../../../../../src/modules/configPreset/configPreset-registry';
import { computeConfigPresetItem } from '../../../../../src/modules/configPreset/import/configPreset-import-domain';
import { CONFIG_PRESET_REASON_ENTERPRISE_EDITION_REQUIRED } from '../../../../../src/modules/configPreset/import/configPreset-import-types';
import type { ConfigPresetBundleItem, ConfigPresetComputedItem } from '../../../../../src/modules/configPreset/import/configPreset-import-types';
import type { ConfigPresetFamilyDefinition } from '../../../../../src/modules/configPreset/configPreset-types';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';
import { ConfigImportMode } from '../../../../../src/modules/configImport/configImport-types';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;

const findFamily = (id: string) => CONFIG_PRESET_FAMILIES.find((family) => family.id === id)!;
const compute = (family: ConfigPresetFamilyDefinition, id: string, configuration: Record<string, unknown>) => {
  const item: ConfigPresetBundleItem = { type: family.id, id, path: `${id}.json`, configuration };
  return computeConfigPresetItem(context, user, family, item, { created: new Set() }, ConfigImportMode.Overwrite);
};

const computed: ConfigPresetComputedItem = { label: 'Playbooks', translatable: true, exists: true, conflict: true, status: 'overwritten' };
// A family that requires the Enterprise Edition, whatever its importer computes
const futureFamily = (result: ConfigPresetComputedItem = computed) => ({
  ...findFamily('messages'),
  id: 'future',
  requiresEnterpriseEdition: true,
  importer: { compute: vi.fn(async () => result), apply: vi.fn() },
}) as ConfigPresetFamilyDefinition;

beforeEach(() => {
  enterpriseEdition.enabled = true;
});

describe('Import of a family that requires the Enterprise Edition (compute)', () => {
  it('computes the item as its importer does on a platform that has the Enterprise Edition', async () => {
    expect(await compute(futureFamily(), 'item', {})).toEqual(computed);
  });

  it('skips the item, with the reason, on a platform without the Enterprise Edition', async () => {
    enterpriseEdition.enabled = false;
    expect(await compute(futureFamily(), 'item', {})).toEqual({
      ...computed,
      status: 'skipped',
      reason: CONFIG_PRESET_REASON_ENTERPRISE_EDITION_REQUIRED,
      conflict: false,
    });
  });

  it('takes a license applied since the last computation into account, without any state to refresh', async () => {
    const family = futureFamily();
    enterpriseEdition.enabled = false;
    expect(await compute(family, 'item', {})).toMatchObject({ status: 'skipped' });
    enterpriseEdition.enabled = true;
    expect(await compute(family, 'item', {})).toEqual(computed);
  });

  it('keeps an item that is invalid as failed, with its own reason, whatever the edition', async () => {
    const failed: ConfigPresetComputedItem = { ...computed, status: 'failed', reason: 'invalid' };
    enterpriseEdition.enabled = false;
    expect(await compute(futureFamily(failed), 'item', {})).toEqual(failed);
  });

  it('leaves the families that do not require it alone', async () => {
    enterpriseEdition.enabled = false;
    expect(await compute(findFamily('messages'), 'banner', { platform_banner_text: 'Hello' })).toMatchObject({ status: 'overwritten' });
  });
});
