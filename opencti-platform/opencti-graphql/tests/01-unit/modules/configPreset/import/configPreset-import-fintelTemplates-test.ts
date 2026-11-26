import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../../src/modules/fintelTemplate/fintelTemplate-import', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/modules/fintelTemplate/fintelTemplate-import')>()),
  importFintelTemplate: vi.fn(),
}));

import { importFintelTemplate } from '../../../../../src/modules/fintelTemplate/fintelTemplate-import';
import { CONFIG_PRESET_FAMILIES } from '../../../../../src/modules/configPreset/configPreset-registry';
import type { ConfigPresetBundleItem, ConfigPresetComputedItem, ConfigPresetImportPlan } from '../../../../../src/modules/configPreset/import/configPreset-import-types';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';
import { ConfigImportMode } from '../../../../../src/modules/configImport/configImport-types';
import { reportFintelTemplate } from '../configPreset-fintelTemplates-fixtures';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const family = CONFIG_PRESET_FAMILIES.find(({ id }) => id === 'fintelTemplates')!;
const bundleId = reportFintelTemplate.standard_id;
const configuration = { standard_id: bundleId, name: 'Executive Summary', settings_types: ['Report'], default: true };
const item = (config: Record<string, unknown>, id: string = bundleId): ConfigPresetBundleItem => ({
  type: 'fintelTemplates',
  id,
  path: `customization/fintel_templates/${id}.json`,
  configuration: config,
});
// The plan of the preview, which reserves the names of the earlier items; the one of a real import has none
const previewPlan = (): ConfigPresetImportPlan => ({ created: new Set(), fintelTemplateNames: new Set(), renamedFintelTemplateIds: new Set() });

beforeEach(() => {
  vi.resetAllMocks();
});

describe('Fintel templates import (registry)', () => {
  it('is importable, in the Customization group, for the Enterprise Edition only, offers overwrite or a copy, and can be scoped to an entity type', () => {
    expect(family.importer).toBeDefined();
    expect(family.importModes).toEqual(['OVERWRITE', 'COPY']);
    expect(family.requiresEnterpriseEdition).toBe(true);
    expect(family.group).toEqual({ id: 'customization', label: 'Customization' });
    expect(family.directory).toBe('customization/fintel_templates');
    expect(family.scopeKey).toBe('settings_types');
  });

  it('computes the item with a dry run of the module, named with its entity type and marked as the default it is, the names of the preview reserved', async () => {
    vi.mocked(importFintelTemplate).mockResolvedValue({ status: 'overwritten', exists: true, existsAsDefault: true });
    const plan = previewPlan();
    const computed = await family.importer!.compute(context, user, item(configuration), plan, ConfigImportMode.Overwrite);
    expect(importFintelTemplate).toHaveBeenCalledWith(context, user, configuration, {
      mode: ConfigImportMode.Overwrite,
      dryRun: true,
      reservedNames: plan.fintelTemplateNames,
      renamedIds: plan.renamedFintelTemplateIds,
    });
    expect(computed).toMatchObject({ label: 'Executive Summary (Report)', translatable: false, isDefault: true, existsAsDefault: true, status: 'overwritten', exists: true, conflict: true });
  });

  it('reserves nothing during a real import: an item that fails leaves no name to the next ones, which read the platform', async () => {
    vi.mocked(importFintelTemplate).mockResolvedValue({ status: 'created', exists: true });
    const realImportPlan: ConfigPresetImportPlan = { created: new Set(), targets: new Map() };
    await family.importer!.compute(context, user, item(configuration), realImportPlan, ConfigImportMode.Copy);
    expect(vi.mocked(importFintelTemplate).mock.calls[0][3]).toMatchObject({ reservedNames: undefined, renamedIds: undefined });
    expect(realImportPlan).toEqual({ created: new Set(), targets: new Map() });
  });

  it('fails an item whose id is not the standard id of its configuration, without asking the module', async () => {
    const otherId = 'finteltemplate--7a8b9c0d-1e2f-5a3b-9c4d-5e6f7a8b9c0d';
    for (const [config, id] of [[configuration, otherId], [{ ...configuration, standard_id: 'x' }, 'x']] as const) {
      expect(await family.importer!.compute(context, user, item(config, id), previewPlan(), ConfigImportMode.Overwrite)).toMatchObject({
        status: 'failed',
        reason: 'The standard id of the fintel template does not match its id',
        label: 'Executive Summary (Report)',
      });
    }
    expect(importFintelTemplate).not.toHaveBeenCalled();
  });

  it('applies the item with the module, says when the real import differs from the preview, and fails with the reason of the module', async () => {
    const computed = { status: 'created' } as ConfigPresetComputedItem;
    vi.mocked(importFintelTemplate).mockResolvedValue({ status: 'created', exists: false });
    expect(await family.importer!.apply(context, user, item(configuration), computed, ConfigImportMode.Copy, previewPlan())).toBeUndefined();
    expect(importFintelTemplate).toHaveBeenCalledWith(context, user, configuration, { mode: ConfigImportMode.Copy });
    vi.mocked(importFintelTemplate).mockResolvedValue({ status: 'skipped', exists: true, reason: 'Already up to date' });
    expect(await family.importer!.apply(context, user, item(configuration), computed, ConfigImportMode.Overwrite, previewPlan()))
      .toEqual({ status: 'skipped', reason: 'Already up to date' });
    vi.mocked(importFintelTemplate).mockResolvedValue({ status: 'failed', exists: true, reason: 'The entity type of the fintel template cannot change' });
    await expect(family.importer!.apply(context, user, item(configuration), computed, ConfigImportMode.Overwrite, previewPlan()))
      .rejects.toThrow('The entity type of the fintel template cannot change');
  });
});
