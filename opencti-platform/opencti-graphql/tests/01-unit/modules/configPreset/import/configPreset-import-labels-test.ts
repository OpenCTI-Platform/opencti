import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../../src/modules/label/label-import', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/modules/label/label-import')>()),
  importLabel: vi.fn(),
}));

import { getLabelStandardId, importLabel } from '../../../../../src/modules/label/label-import';
import { CONFIG_PRESET_FAMILIES } from '../../../../../src/modules/configPreset/configPreset-registry';
import type { ConfigPresetBundleItem, ConfigPresetComputedItem, ConfigPresetImportPlan } from '../../../../../src/modules/configPreset/import/configPreset-import-types';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';
import { ConfigImportMode } from '../../../../../src/modules/configImport/configImport-types';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const family = CONFIG_PRESET_FAMILIES.find(({ id }) => id === 'labels')!;
const plan: ConfigPresetImportPlan = { created: new Set() };
const aptId = getLabelStandardId('APT');
const item = (configuration: Record<string, unknown>, id = aptId): ConfigPresetBundleItem => ({ type: 'labels', id, path: `taxonomy/labels/${id}.json`, configuration });
const computed = {} as ConfigPresetComputedItem;

beforeEach(() => {
  vi.resetAllMocks();
});

describe('Labels import (registry)', () => {
  it('is importable and offers no choice of mode: a label has no copy', () => {
    expect(family.importer).toBeDefined();
    expect(family.importModes).toBeUndefined();
  });

  it('computes the item with a dry run of the module, named by its value', async () => {
    vi.mocked(importLabel).mockResolvedValue({ status: 'overwritten', exists: true });
    const configuration = { value: 'APT', color: '#ff0000' };
    const result = await family.importer!.compute(context, user, item(configuration), plan, ConfigImportMode.Overwrite);
    expect(importLabel).toHaveBeenCalledWith(context, user, configuration, { mode: ConfigImportMode.Overwrite, dryRun: true });
    expect(result).toMatchObject({ label: 'APT', translatable: false, status: 'overwritten', exists: true, conflict: true });
  });

  it('reports a label that does not exist as created, without conflict', async () => {
    vi.mocked(importLabel).mockResolvedValue({ status: 'created', exists: false });
    expect(await family.importer!.compute(context, user, item({ value: 'APT' }), plan, ConfigImportMode.Overwrite)).toMatchObject({ status: 'created', exists: false, conflict: false });
  });

  it('fails an item whose id is not the standard id of its value, without asking the module', async () => {
    const result = await family.importer!.compute(context, user, item({ value: 'APT' }, getLabelStandardId('Other')), plan, ConfigImportMode.Overwrite);
    expect(result).toMatchObject({ status: 'failed', label: 'APT', reason: 'The standard id of the label does not match its value' });
    expect(importLabel).not.toHaveBeenCalled();
  });

  it('leaves a configuration without a value to the module, which refuses it, and names the item by its id', async () => {
    vi.mocked(importLabel).mockResolvedValue({ status: 'failed', code: 'invalid', reason: 'value: Invalid input', exists: false });
    expect(await family.importer!.compute(context, user, item({}), plan, ConfigImportMode.Overwrite)).toMatchObject({ status: 'failed', label: aptId, reason: 'value: Invalid input' });
  });

  it('leaves a blank value to the module, which refuses it, instead of failing to derive its id', async () => {
    vi.mocked(importLabel).mockResolvedValue({ status: 'failed', code: 'invalid', reason: 'value: Label value is required', exists: false });
    expect(await family.importer!.compute(context, user, item({ value: '  ' }), plan, ConfigImportMode.Overwrite)).toMatchObject({ status: 'failed', reason: 'value: Label value is required' });
    expect(importLabel).toHaveBeenCalledOnce();
  });

  it('applies through the module, reports a status that differs from the computed one, and throws on a failure', async () => {
    const configuration = { value: 'APT', color: '#ff0000' };
    vi.mocked(importLabel).mockResolvedValueOnce({ status: 'created', exists: false });
    expect(await family.importer!.apply(context, user, item(configuration), { ...computed, status: 'created' }, ConfigImportMode.Overwrite, plan)).toBeUndefined();
    expect(importLabel).toHaveBeenCalledWith(context, user, configuration, { mode: ConfigImportMode.Overwrite });
    // Created by another import since the dry run
    vi.mocked(importLabel).mockResolvedValueOnce({ status: 'skipped', code: 'unchanged', exists: true });
    expect(await family.importer!.apply(context, user, item(configuration), { ...computed, status: 'created' }, ConfigImportMode.Overwrite, plan)).toBe('skipped');
    vi.mocked(importLabel).mockResolvedValueOnce({ status: 'failed', code: 'invalid', reason: 'value: Invalid input', exists: false });
    await expect(family.importer!.apply(context, user, item(configuration), { ...computed, status: 'created' }, ConfigImportMode.Overwrite, plan)).rejects.toThrow('value: Invalid input');
  });
});
