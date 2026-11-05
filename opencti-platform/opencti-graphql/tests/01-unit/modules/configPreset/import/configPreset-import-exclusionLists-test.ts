import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../../src/modules/exclusionList/exclusionList-import', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/modules/exclusionList/exclusionList-import')>()),
  importExclusionList: vi.fn(),
}));

import { importExclusionList } from '../../../../../src/modules/exclusionList/exclusionList-import';
import { CONFIG_PRESET_FAMILIES } from '../../../../../src/modules/configPreset/configPreset-registry';
import type { ConfigPresetBundleItem, ConfigPresetComputedItem, ConfigPresetImportPlan } from '../../../../../src/modules/configPreset/import/configPreset-import-types';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';
import { ConfigImportMode } from '../../../../../src/modules/configImport/configImport-types';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const family = CONFIG_PRESET_FAMILIES.find(({ id }) => id === 'exclusionLists')!;
const plan: ConfigPresetImportPlan = { created: new Set() };
// The id of an exclusion list is random: the one of the platform it was exported from
const bundleId = '3f1d0c4e-7a52-4b8e-9f3a-1c2d3e4f5a6b';
const configuration = { name: 'Public DNS resolvers', exclusion_list_entity_types: ['IPv4-Addr'] };
const file = { path: `customization/exclusion_lists/${bundleId}.txt`, read: vi.fn() };
const item = (config: Record<string, unknown>, id = bundleId): ConfigPresetBundleItem => ({
  type: 'exclusionLists',
  id,
  path: `customization/exclusion_lists/${id}.json`,
  configuration: config,
  file,
});
const computed = {} as ConfigPresetComputedItem;

beforeEach(() => {
  vi.resetAllMocks();
});

describe('Exclusion lists import (registry)', () => {
  it('is importable, in the Customization group, and offers no choice of mode: an exclusion list has no copy', () => {
    expect(family.importer).toBeDefined();
    expect(family.importModes).toBeUndefined();
    expect(family.group).toEqual({ id: 'customization', label: 'Customization' });
    expect(family.directory).toBe('customization/exclusion_lists');
  });

  it('computes the item with a dry run of the module, with the file of the item, named by its name', async () => {
    vi.mocked(importExclusionList).mockResolvedValue({ status: 'overwritten', exists: true });
    const result = await family.importer!.compute(context, user, item(configuration), plan, ConfigImportMode.Overwrite);
    expect(importExclusionList).toHaveBeenCalledWith(context, user, configuration, file, { mode: ConfigImportMode.Overwrite, dryRun: true });
    expect(result).toMatchObject({ label: 'Public DNS resolvers', translatable: false, status: 'overwritten', exists: true, conflict: true });
  });

  it('gives no file to the module for an item whose zip has none, which refuses it', async () => {
    vi.mocked(importExclusionList).mockResolvedValue({ status: 'failed', code: 'file_missing', reason: 'The file of the values of the exclusion list is missing from the bundle', exists: false });
    const result = await family.importer!.compute(context, user, { ...item(configuration), file: undefined }, plan, ConfigImportMode.Overwrite);
    expect(importExclusionList).toHaveBeenCalledWith(context, user, configuration, undefined, { mode: ConfigImportMode.Overwrite, dryRun: true });
    expect(result).toMatchObject({ status: 'failed', code: 'file_missing' });
  });

  it('does not check the id of the item against its content: it is random, the list is found by its name', async () => {
    vi.mocked(importExclusionList).mockResolvedValue({ status: 'created', exists: false });
    const result = await family.importer!.compute(context, user, item(configuration, 'any-other-id'), plan, ConfigImportMode.Overwrite);
    expect(result).toMatchObject({ status: 'created', exists: false, conflict: false });
    expect(importExclusionList).toHaveBeenCalledTimes(1);
  });

  it('reports a list that the platform already has as skipped when nothing differs, and a name that several lists have as a failure', async () => {
    vi.mocked(importExclusionList).mockResolvedValueOnce({ status: 'skipped', code: 'unchanged', exists: true, reason: 'Already up to date' });
    expect(await family.importer!.compute(context, user, item(configuration), plan, ConfigImportMode.Overwrite)).toMatchObject({ status: 'skipped', code: 'unchanged', reason: 'Already up to date' });
    vi.mocked(importExclusionList).mockResolvedValueOnce({ status: 'failed', code: 'ambiguous', reason: 'Several exclusion lists have this name', exists: true });
    expect(await family.importer!.compute(context, user, item(configuration), plan, ConfigImportMode.Overwrite)).toMatchObject({ status: 'failed', reason: 'Several exclusion lists have this name' });
  });

  it('leaves a configuration without a name to the module, which refuses it, and names the item by its id', async () => {
    vi.mocked(importExclusionList).mockResolvedValue({ status: 'failed', code: 'invalid', reason: 'name: Invalid input', exists: false });
    expect(await family.importer!.compute(context, user, item({ exclusion_list_entity_types: [] }), plan, ConfigImportMode.Overwrite)).toMatchObject({ status: 'failed', label: bundleId, reason: 'name: Invalid input' });
  });

  it('applies through the module with the file, reports a status that differs from the computed one, and throws on a failure', async () => {
    vi.mocked(importExclusionList).mockResolvedValueOnce({ status: 'created', exists: false });
    expect(await family.importer!.apply(context, user, item(configuration), { ...computed, status: 'created' }, ConfigImportMode.Overwrite, plan)).toBeUndefined();
    expect(importExclusionList).toHaveBeenCalledWith(context, user, configuration, file, { mode: ConfigImportMode.Overwrite });
    vi.mocked(importExclusionList).mockResolvedValueOnce({ status: 'skipped', code: 'unchanged', exists: true });
    expect(await family.importer!.apply(context, user, item(configuration), { ...computed, status: 'created' }, ConfigImportMode.Overwrite, plan)).toBe('skipped');
    vi.mocked(importExclusionList).mockResolvedValueOnce({ status: 'failed', code: 'file_too_large', reason: 'The file of the values of the exclusion list is too large', exists: true });
    await expect(family.importer!.apply(context, user, item(configuration), { ...computed, status: 'created' }, ConfigImportMode.Overwrite, plan)).rejects.toThrow('too large');
  });
});
