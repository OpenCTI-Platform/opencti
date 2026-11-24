import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../../src/modules/form/form-import', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/modules/form/form-import')>()),
  importFormIntake: vi.fn(),
}));

import { importFormIntake } from '../../../../../src/modules/form/form-import';
import { CONFIG_PRESET_FAMILIES } from '../../../../../src/modules/configPreset/configPreset-registry';
import type { ConfigPresetBundleItem, ConfigPresetComputedItem, ConfigPresetImportPlan } from '../../../../../src/modules/configPreset/import/configPreset-import-types';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';
import { ConfigImportMode } from '../../../../../src/modules/configImport/configImport-types';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const family = CONFIG_PRESET_FAMILIES.find(({ id }) => id === 'formIntakes')!;
const plan: ConfigPresetImportPlan = { created: new Set() };
// The id of a bundle item is the standard id of the platform it comes from: random, it says nothing of the content
const BUNDLE_ID = 'c7d2e4f1-3b4f-4c6d-8e9f-0a1b2c3d4e5f';
const configuration = { name: 'Incident intake', form_schema: { version: '2.0', mainEntityType: 'Incident', fields: [] }, active: true };
const item = (config: Record<string, unknown> = configuration): ConfigPresetBundleItem => ({
  type: 'integrations.formIntakes',
  id: BUNDLE_ID,
  path: `integrations/form_intakes/${BUNDLE_ID}.json`,
  configuration: config,
});
const computed = {} as ConfigPresetComputedItem;

beforeEach(() => {
  vi.resetAllMocks();
});

describe('Form intakes import (registry)', () => {
  it('is importable and offers the choice between overwriting a form and adding a copy of it', () => {
    expect(family.importer).toBeDefined();
    expect(family.importModes).toEqual([ConfigImportMode.Overwrite, ConfigImportMode.Copy]);
  });

  it('shares the keys that the forms of a dry run reserve through the plan, and creates them when the plan has none', async () => {
    const formIntakeKeys = new Set<string>();
    vi.mocked(importFormIntake).mockResolvedValue({ status: 'created', exists: false });
    await family.importer!.compute(context, user, item(), { ...plan, formIntakeKeys }, ConfigImportMode.Overwrite);
    expect(importFormIntake).toHaveBeenCalledWith(context, user, configuration, { mode: ConfigImportMode.Overwrite, dryRun: true, reservedKeys: formIntakeKeys });
    const withoutKeys: ConfigPresetImportPlan = { created: new Set() };
    await family.importer!.compute(context, user, item(), withoutKeys, ConfigImportMode.Overwrite);
    expect(withoutKeys.formIntakeKeys).toBeInstanceOf(Set);
  });

  it('names the item by the trimmed name of the form, not by its bundle id, and falls back to the id when there is no name', async () => {
    vi.mocked(importFormIntake).mockResolvedValue({ status: 'overwritten', exists: true });
    expect(await family.importer!.compute(context, user, item({ ...configuration, name: '  Incident intake ' }), plan, ConfigImportMode.Overwrite))
      .toMatchObject({ label: 'Incident intake', translatable: false, status: 'overwritten', exists: true, conflict: true });
    vi.mocked(importFormIntake).mockResolvedValue({ status: 'failed', code: 'invalid', reason: 'name: Invalid input', exists: false });
    expect(await family.importer!.compute(context, user, item({ form_schema: {} }), plan, ConfigImportMode.Overwrite))
      .toMatchObject({ status: 'failed', label: BUNDLE_ID, reason: 'name: Invalid input' });
  });

  it('shows a created form and an overwritten one as disabled, and a form left as it is with its own state', async () => {
    vi.mocked(importFormIntake).mockResolvedValue({ status: 'created', exists: false });
    expect(await family.importer!.compute(context, user, item(), plan, ConfigImportMode.Overwrite)).toMatchObject({ status: 'created', isEnabled: false, conflict: false });
    vi.mocked(importFormIntake).mockResolvedValue({ status: 'overwritten', exists: true });
    expect((await family.importer!.compute(context, user, item(), plan, ConfigImportMode.Overwrite)).isEnabled).toBe(false);
    vi.mocked(importFormIntake).mockResolvedValue({ status: 'skipped', code: 'unchanged', exists: true });
    expect((await family.importer!.compute(context, user, item(), plan, ConfigImportMode.Overwrite)).isEnabled).toBeNull();
  });

  it('shows the code of a refusal of the module', async () => {
    vi.mocked(importFormIntake).mockResolvedValue({ status: 'failed', code: 'ambiguous', reason: 'Several form intakes have this name', exists: true });
    expect(await family.importer!.compute(context, user, item(), plan, ConfigImportMode.Overwrite)).toMatchObject({ status: 'failed', code: 'ambiguous', reason: 'Several form intakes have this name' });
  });

  it('applies through the module, reports a status that differs from the computed one, and throws on a failure', async () => {
    vi.mocked(importFormIntake).mockResolvedValueOnce({ status: 'created', exists: false });
    expect(await family.importer!.apply(context, user, item(), { ...computed, status: 'created' }, ConfigImportMode.Overwrite, plan)).toBeUndefined();
    expect(importFormIntake).toHaveBeenCalledWith(context, user, configuration, { mode: ConfigImportMode.Overwrite });
    // Created by another import since the dry run
    vi.mocked(importFormIntake).mockResolvedValueOnce({ status: 'skipped', code: 'unchanged', exists: true });
    expect(await family.importer!.apply(context, user, item(), { ...computed, status: 'created' }, ConfigImportMode.Overwrite, plan)).toBe('skipped');
    vi.mocked(importFormIntake).mockResolvedValueOnce({ status: 'failed', code: 'invalid', reason: 'name: Invalid input', exists: false });
    await expect(family.importer!.apply(context, user, item(), { ...computed, status: 'created' }, ConfigImportMode.Overwrite, plan)).rejects.toThrow('name: Invalid input');
  });
});
