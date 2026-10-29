import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../../src/modules/entitySetting/entitySetting-import', () => ({ importHiddenEntityTypes: vi.fn() }));

import { importHiddenEntityTypes } from '../../../../../src/modules/entitySetting/entitySetting-import';
import { CONFIG_PRESET_FAMILIES } from '../../../../../src/modules/configPreset/configPreset-registry';
import type { ConfigPresetBundleItem, ConfigPresetComputedItem, ConfigPresetImportPlan } from '../../../../../src/modules/configPreset/import/configPreset-import-types';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';
import { ConfigImportMode } from '../../../../../src/modules/configImport/configImport-types';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const family = CONFIG_PRESET_FAMILIES.find(({ id }) => id === 'hiddenEntityTypes')!;
const plan: ConfigPresetImportPlan = { created: new Set() };
const item = (configuration: Record<string, unknown>, id = 'hiddenEntityTypes'): ConfigPresetBundleItem => ({ type: 'hiddenEntityTypes', id, path: `${id}.json`, configuration });
const computed = {} as ConfigPresetComputedItem;

beforeEach(() => {
  vi.resetAllMocks();
});

describe('Hidden entity types import (registry)', () => {
  it('is importable, and offers no choice of mode: a setting has no copy', () => {
    expect(family.importer).toBeDefined();
    expect(family.importModes).toBeUndefined();
  });

  it('computes the item with a dry run of the module, and previews the types it would hide', async () => {
    vi.mocked(importHiddenEntityTypes).mockResolvedValue({ status: 'overwritten', exists: true, configuration: { hidden_entity_types: ['Report', 'Malware'] } });
    const configuration = { hidden_entity_types: ['Report', 'Malware'] };
    const result = await family.importer!.compute(context, user, item(configuration), plan, ConfigImportMode.Overwrite);
    expect(importHiddenEntityTypes).toHaveBeenCalledWith(context, user, configuration, { mode: ConfigImportMode.Overwrite, dryRun: true });
    expect(result).toMatchObject({
      label: 'Hidden entity types',
      translatable: true,
      status: 'overwritten',
      exists: true,
      fields: [{ key: 'hidden_entity_types', value: 'Malware, Report' }],
    });
  });

  it('previews no value for an empty list, and nothing for a configuration the module refused', async () => {
    vi.mocked(importHiddenEntityTypes).mockResolvedValueOnce({ status: 'overwritten', exists: true, configuration: { hidden_entity_types: [] } });
    expect((await family.importer!.compute(context, user, item({ hidden_entity_types: [] }), plan, ConfigImportMode.Overwrite)).fields).toEqual([{ key: 'hidden_entity_types', value: null }]);
    vi.mocked(importHiddenEntityTypes).mockResolvedValueOnce({ status: 'failed', code: 'invalid', reason: 'hidden_entity_types: Invalid input', exists: true });
    expect(await family.importer!.compute(context, user, item({}), plan, ConfigImportMode.Overwrite)).toMatchObject({ status: 'failed', reason: 'hidden_entity_types: Invalid input', fields: [] });
  });

  it('fails an item that is not the hidden entity types, without asking the module', async () => {
    expect(await family.importer!.compute(context, user, item({ hidden_entity_types: [] }, 'other'), plan, ConfigImportMode.Overwrite))
      .toMatchObject({ status: 'failed', reason: 'Unexpected item id' });
    expect(importHiddenEntityTypes).not.toHaveBeenCalled();
  });

  it('applies through the module, reports a status that differs from the computed one, and throws on a failure', async () => {
    vi.mocked(importHiddenEntityTypes).mockResolvedValueOnce({ status: 'overwritten', exists: true });
    expect(await family.importer!.apply(context, user, item({ hidden_entity_types: [] }), { ...computed, status: 'overwritten' }, ConfigImportMode.Overwrite)).toBeUndefined();
    expect(importHiddenEntityTypes).toHaveBeenCalledWith(context, user, { hidden_entity_types: [] }, { mode: ConfigImportMode.Overwrite });
    vi.mocked(importHiddenEntityTypes).mockResolvedValueOnce({ status: 'skipped', code: 'nothing_to_import', exists: true });
    expect(await family.importer!.apply(context, user, item({ hidden_entity_types: [] }), { ...computed, status: 'overwritten' }, ConfigImportMode.Overwrite)).toBe('skipped');
    vi.mocked(importHiddenEntityTypes).mockResolvedValueOnce({ status: 'failed', code: 'cannot_be_hidden', reason: 'Entity types that cannot be hidden: Missing', exists: true });
    await expect(family.importer!.apply(context, user, item({ hidden_entity_types: ['Missing'] }), computed, ConfigImportMode.Overwrite)).rejects.toThrow('Entity types that cannot be hidden: Missing');
  });
});
