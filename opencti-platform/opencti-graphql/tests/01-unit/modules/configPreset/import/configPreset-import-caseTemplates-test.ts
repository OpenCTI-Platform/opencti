import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../../src/modules/case/case-template/case-template-import', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/modules/case/case-template/case-template-import')>()),
  importCaseTemplate: vi.fn(),
}));

import { importCaseTemplate } from '../../../../../src/modules/case/case-template/case-template-import';
import { CONFIG_PRESET_FAMILIES } from '../../../../../src/modules/configPreset/configPreset-registry';
import type { ConfigPresetBundleItem, ConfigPresetComputedItem, ConfigPresetImportPlan } from '../../../../../src/modules/configPreset/import/configPreset-import-types';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';
import { ConfigImportMode } from '../../../../../src/modules/configImport/configImport-types';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const family = CONFIG_PRESET_FAMILIES.find(({ id }) => id === 'caseTemplates')!;
const plan: ConfigPresetImportPlan = { created: new Set() };
// The id of a case template is random: the one of the platform it was exported from
const bundleId = 'case-template--1a80c59c-d839-4984-af04-04f3286d8f89';
const configuration = { name: 'Phishing triage', description: 'Triage', tasks: [{ name: 'Block sender' }] };
const item = (config: Record<string, unknown>, id = bundleId): ConfigPresetBundleItem => ({ type: 'caseTemplates', id, path: `taxonomy/case_templates/${id}.json`, configuration: config });
const computed = {} as ConfigPresetComputedItem;

beforeEach(() => {
  vi.resetAllMocks();
});

describe('Case templates import (registry)', () => {
  it('is importable and offers no choice of mode: a case template has no copy', () => {
    expect(family.importer).toBeDefined();
    expect(family.importModes).toBeUndefined();
  });

  it('computes the item with a dry run of the module, named by its name', async () => {
    vi.mocked(importCaseTemplate).mockResolvedValue({ status: 'overwritten', exists: true });
    const result = await family.importer!.compute(context, user, item(configuration), plan, ConfigImportMode.Overwrite);
    expect(importCaseTemplate).toHaveBeenCalledWith(context, user, configuration, { mode: ConfigImportMode.Overwrite, dryRun: true });
    expect(result).toMatchObject({ label: 'Phishing triage', translatable: false, status: 'overwritten', exists: true, conflict: true });
  });

  it('does not check the id of the item against its content: it is random, the template is found by its name', async () => {
    vi.mocked(importCaseTemplate).mockResolvedValue({ status: 'created', exists: false });
    const result = await family.importer!.compute(context, user, item(configuration, 'case-template--any-other-id'), plan, ConfigImportMode.Overwrite);
    expect(result).toMatchObject({ status: 'created', exists: false, conflict: false });
    expect(importCaseTemplate).toHaveBeenCalledTimes(1);
  });

  it('reports a template that the platform already has as skipped when nothing differs', async () => {
    vi.mocked(importCaseTemplate).mockResolvedValue({ status: 'skipped', code: 'unchanged', exists: true, reason: 'Already up to date' });
    expect(await family.importer!.compute(context, user, item(configuration), plan, ConfigImportMode.Overwrite)).toMatchObject({ status: 'skipped', exists: true, reason: 'Already up to date' });
  });

  it('reports a name that several templates have as a failure of the item', async () => {
    vi.mocked(importCaseTemplate).mockResolvedValue({ status: 'failed', code: 'ambiguous', reason: 'Several case templates have this name', exists: true });
    expect(await family.importer!.compute(context, user, item(configuration), plan, ConfigImportMode.Overwrite))
      .toMatchObject({ status: 'failed', reason: 'Several case templates have this name' });
  });

  it('leaves a configuration without a name to the module, which refuses it, and names the item by its id', async () => {
    vi.mocked(importCaseTemplate).mockResolvedValue({ status: 'failed', code: 'invalid', reason: 'name: Invalid input', exists: false });
    expect(await family.importer!.compute(context, user, item({ tasks: [] }), plan, ConfigImportMode.Overwrite)).toMatchObject({ status: 'failed', label: bundleId, reason: 'name: Invalid input' });
  });

  it('applies through the module, reports a status that differs from the computed one, and throws on a failure', async () => {
    vi.mocked(importCaseTemplate).mockResolvedValueOnce({ status: 'created', exists: false });
    expect(await family.importer!.apply(context, user, item(configuration), { ...computed, status: 'created' }, ConfigImportMode.Overwrite, plan)).toBeUndefined();
    expect(importCaseTemplate).toHaveBeenCalledWith(context, user, configuration, { mode: ConfigImportMode.Overwrite });
    vi.mocked(importCaseTemplate).mockResolvedValueOnce({ status: 'skipped', code: 'unchanged', exists: true });
    expect(await family.importer!.apply(context, user, item(configuration), { ...computed, status: 'created' }, ConfigImportMode.Overwrite, plan)).toBe('skipped');
    vi.mocked(importCaseTemplate).mockResolvedValueOnce({ status: 'failed', code: 'ambiguous', reason: 'Several case templates have this name', exists: true });
    await expect(family.importer!.apply(context, user, item(configuration), { ...computed, status: 'created' }, ConfigImportMode.Overwrite, plan)).rejects.toThrow('Several case templates');
  });
});
