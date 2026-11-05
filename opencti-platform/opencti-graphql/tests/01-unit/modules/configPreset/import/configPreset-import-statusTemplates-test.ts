import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../../src/modules/statusTemplate/statusTemplate-import', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/modules/statusTemplate/statusTemplate-import')>()),
  importStatusTemplate: vi.fn(),
}));

import { getStatusTemplateStandardId, importStatusTemplate } from '../../../../../src/modules/statusTemplate/statusTemplate-import';
import { CONFIG_PRESET_FAMILIES } from '../../../../../src/modules/configPreset/configPreset-registry';
import type { ConfigPresetBundleItem, ConfigPresetComputedItem, ConfigPresetImportPlan } from '../../../../../src/modules/configPreset/import/configPreset-import-types';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';
import { ConfigImportMode } from '../../../../../src/modules/configImport/configImport-types';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const family = CONFIG_PRESET_FAMILIES.find(({ id }) => id === 'statusTemplates')!;
const plan: ConfigPresetImportPlan = { created: new Set() };
const templateId = getStatusTemplateStandardId('Escalated');
const configuration = { name: 'Escalated', color: '#e91e63' };
const item = (config: Record<string, unknown>, id = templateId): ConfigPresetBundleItem => ({ type: 'statusTemplates', id, path: `taxonomy/status_templates/${id}.json`, configuration: config });
const computed = {} as ConfigPresetComputedItem;

beforeEach(() => {
  vi.resetAllMocks();
});

describe('Status templates import (registry)', () => {
  it('is importable and offers no choice of mode: a status template has no copy', () => {
    expect(family.importer).toBeDefined();
    expect(family.importModes).toBeUndefined();
  });

  it('computes the item with a dry run of the module, named by its name', async () => {
    vi.mocked(importStatusTemplate).mockResolvedValue({ status: 'overwritten', exists: true });
    const result = await family.importer!.compute(context, user, item(configuration), plan, ConfigImportMode.Overwrite);
    expect(importStatusTemplate).toHaveBeenCalledWith(context, user, configuration, { mode: ConfigImportMode.Overwrite, dryRun: true });
    expect(result).toMatchObject({ label: 'Escalated', translatable: false, status: 'overwritten', exists: true, conflict: true });
  });

  it('reports a template that the platform already has as skipped when nothing differs', async () => {
    vi.mocked(importStatusTemplate).mockResolvedValue({ status: 'skipped', code: 'unchanged', exists: true, reason: 'Already up to date' });
    expect(await family.importer!.compute(context, user, item(configuration), plan, ConfigImportMode.Overwrite))
      .toMatchObject({ status: 'skipped', exists: true, reason: 'Already up to date' });
  });

  it('accepts an id computed from the name whatever its case and surrounding spaces, as the platform does', async () => {
    vi.mocked(importStatusTemplate).mockResolvedValue({ status: 'created', exists: false });
    expect(await family.importer!.compute(context, user, item({ ...configuration, name: ' ESCALATED ' }), plan, ConfigImportMode.Overwrite))
      .toMatchObject({ status: 'created', exists: false, conflict: false });
  });

  it('fails an item whose id is not the standard id of its name, without asking the module', async () => {
    const result = await family.importer!.compute(context, user, item(configuration, getStatusTemplateStandardId('Other')), plan, ConfigImportMode.Overwrite);
    expect(result).toMatchObject({ status: 'failed', label: 'Escalated', reason: 'The standard id of the status template does not match its name' });
    expect(importStatusTemplate).not.toHaveBeenCalled();
  });

  it.each([[''], ['   '], [undefined], [42]])('leaves a blank or missing name (%j) to the module, which refuses it, instead of aborting the preview', async (name) => {
    vi.mocked(importStatusTemplate).mockResolvedValue({ status: 'failed', code: 'invalid', reason: 'name: Invalid input', exists: false });
    expect(await family.importer!.compute(context, user, item({ name, color: '#e91e63' }), plan, ConfigImportMode.Overwrite))
      .toMatchObject({ status: 'failed', reason: 'name: Invalid input' });
    expect(importStatusTemplate).toHaveBeenCalledTimes(1);
  });

  it('leaves a configuration without a name to the module, which refuses it, and names the item by its id', async () => {
    vi.mocked(importStatusTemplate).mockResolvedValue({ status: 'failed', code: 'invalid', reason: 'name: Invalid input', exists: false });
    expect(await family.importer!.compute(context, user, item({ color: '#e91e63' }), plan, ConfigImportMode.Overwrite))
      .toMatchObject({ status: 'failed', label: templateId, reason: 'name: Invalid input' });
  });

  it('applies through the module, reports a status that differs from the computed one, and throws on a failure', async () => {
    vi.mocked(importStatusTemplate).mockResolvedValueOnce({ status: 'created', exists: false });
    expect(await family.importer!.apply(context, user, item(configuration), { ...computed, status: 'created' }, ConfigImportMode.Overwrite, plan)).toBeUndefined();
    expect(importStatusTemplate).toHaveBeenCalledWith(context, user, configuration, { mode: ConfigImportMode.Overwrite });
    vi.mocked(importStatusTemplate).mockResolvedValueOnce({ status: 'skipped', code: 'unchanged', exists: true });
    expect(await family.importer!.apply(context, user, item(configuration), { ...computed, status: 'created' }, ConfigImportMode.Overwrite, plan)).toBe('skipped');
    vi.mocked(importStatusTemplate).mockResolvedValueOnce({ status: 'failed', code: 'invalid', reason: 'name: Invalid input', exists: false });
    await expect(family.importer!.apply(context, user, item(configuration), { ...computed, status: 'created' }, ConfigImportMode.Overwrite, plan)).rejects.toThrow('name: Invalid input');
  });
});
