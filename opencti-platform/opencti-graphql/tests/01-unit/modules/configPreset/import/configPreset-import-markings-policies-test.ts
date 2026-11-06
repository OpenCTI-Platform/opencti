import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../../src/modules/markingDefinition/marking-import', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/modules/markingDefinition/marking-import')>()),
  importMarking: vi.fn(),
}));
vi.mock('../../../../../src/modules/settings/settings-import', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/modules/settings/settings-import')>()),
  importPolicies: vi.fn(),
}));

import { importMarking, markingStandardId } from '../../../../../src/modules/markingDefinition/marking-import';
import { importPolicies } from '../../../../../src/modules/settings/settings-import';
import { CONFIG_PRESET_FAMILIES } from '../../../../../src/modules/configPreset/configPreset-registry';
import type { ConfigPresetBundleItem, ConfigPresetImportPlan } from '../../../../../src/modules/configPreset/import/configPreset-import-types';
import { ConfigImportMode } from '../../../../../src/modules/configImport/configImport-types';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const overwrite = ConfigImportMode.Overwrite;

const importerOf = (type: string) => CONFIG_PRESET_FAMILIES.find((family) => family.id === type)!.importer!;
const newPlan = (): ConfigPresetImportPlan => ({ created: new Set(), plannedMarkings: new Map() });

const marking = { definition_type: 'INTERNAL', definition: 'INTERNAL:SOC', x_opencti_color: '#123456', x_opencti_order: 7 };
const markingItem: ConfigPresetBundleItem = { type: 'markings', id: markingStandardId('INTERNAL', 'INTERNAL:SOC'), path: 'soc.json', configuration: marking };
const policiesItem: ConfigPresetBundleItem = { type: 'policies', id: 'policies', path: 'policies.json', configuration: { view_all_users: false } };

beforeEach(() => {
  vi.resetAllMocks();
});

describe('Markings import of the config preset', () => {
  it('fails a marking whose bundle id is not the standard id of its definition, without reading the platform', async () => {
    const item = { ...markingItem, id: markingStandardId('INTERNAL', 'INTERNAL:OTHER') };
    const computed = await importerOf('markings').compute(context, user, item, newPlan(), overwrite);
    expect(computed).toMatchObject({ label: 'INTERNAL:SOC', status: 'failed', reason: 'The standard id of the marking does not match its definition' });
    expect(importMarking).not.toHaveBeenCalled();
  });

  it('records in the plan the marking it creates, with its order, for the groups of the same import', async () => {
    vi.mocked(importMarking).mockResolvedValue({ status: 'created', exists: false, configuration: { ...marking, x_opencti_order: null } });
    const plan = newPlan();
    expect(await importerOf('markings').compute(context, user, markingItem, plan, overwrite)).toMatchObject({ status: 'created' });
    expect(importMarking).toHaveBeenCalledWith(context, user, marking, { mode: overwrite, dryRun: true });
    expect(plan.created).toEqual(new Set([`markings/${markingItem.id}`]));
    expect(plan.plannedMarkings).toEqual(new Map([[markingItem.id, { definition_type: 'INTERNAL', definition: 'INTERNAL:SOC', x_opencti_order: 0 }]]));
  });

  it('records the order of a marking it overwrites, and nothing when the order stays the one of the platform', async () => {
    vi.mocked(importMarking).mockResolvedValue({ status: 'overwritten', exists: true, configuration: marking });
    const plan = newPlan();
    await importerOf('markings').compute(context, user, markingItem, plan, overwrite);
    expect(plan.created.size).toEqual(0);
    expect(plan.plannedMarkings?.get(markingItem.id)).toEqual({ definition_type: 'INTERNAL', definition: 'INTERNAL:SOC', x_opencti_order: 7 });
    vi.mocked(importMarking).mockResolvedValue({ status: 'overwritten', exists: true, configuration: { ...marking, x_opencti_order: null } });
    const unordered = newPlan();
    await importerOf('markings').compute(context, user, markingItem, unordered, overwrite);
    expect(unordered.plannedMarkings?.size).toEqual(0);
  });

  it('writes the marking, and fails the item when the module refuses it', async () => {
    const computed = { label: 'INTERNAL:SOC', translatable: false, exists: false, conflict: false, status: 'created' as const };
    vi.mocked(importMarking).mockResolvedValue({ status: 'created', exists: false });
    expect(await importerOf('markings').apply(context, user, markingItem, computed, overwrite, newPlan())).toBeUndefined();
    expect(importMarking).toHaveBeenLastCalledWith(context, user, marking, { mode: overwrite });
    vi.mocked(importMarking).mockResolvedValue({ status: 'failed', code: 'exists', reason: 'Marking already exists', exists: true });
    await expect(importerOf('markings').apply(context, user, markingItem, computed, overwrite, newPlan())).rejects.toThrow('Marking already exists');
  });
});

describe('Policies import of the config preset', () => {
  it('fails an item that is not the policies, without reading the platform', async () => {
    const computed = await importerOf('policies').compute(context, user, { ...policiesItem, id: 'another' }, newPlan(), overwrite);
    expect(computed).toMatchObject({ label: 'Policies', translatable: true, status: 'failed', reason: 'Unexpected item id' });
    expect(importPolicies).not.toHaveBeenCalled();
  });

  it('computes the policies with a dry run, then writes them and reports a status that differs from the computed one', async () => {
    vi.mocked(importPolicies).mockResolvedValue({ status: 'overwritten', exists: true, reason: 'Sets the main organization: Filigran' });
    const computed = await importerOf('policies').compute(context, user, policiesItem, newPlan(), overwrite);
    expect(computed).toMatchObject({ status: 'overwritten', reason: 'Sets the main organization: Filigran' });
    expect(importPolicies).toHaveBeenCalledWith(context, user, policiesItem.configuration, { mode: overwrite, dryRun: true });
    expect(await importerOf('policies').apply(context, user, policiesItem, computed, overwrite, newPlan())).toBeUndefined();
    expect(importPolicies).toHaveBeenLastCalledWith(context, user, policiesItem.configuration, { mode: overwrite });
    vi.mocked(importPolicies).mockResolvedValue({ status: 'skipped', code: 'unchanged', exists: true });
    expect(await importerOf('policies').apply(context, user, policiesItem, computed, overwrite, newPlan())).toEqual('skipped');
  });
});
