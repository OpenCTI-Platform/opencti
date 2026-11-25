import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../../src/modules/customView/customView-import', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/modules/customView/customView-import')>()),
  importCustomView: vi.fn(),
}));

import { importCustomView } from '../../../../../src/modules/customView/customView-import';
import { CONFIG_PRESET_FAMILIES } from '../../../../../src/modules/configPreset/configPreset-registry';
import type { ConfigPresetBundleItem, ConfigPresetComputedItem, ConfigPresetImportPlan } from '../../../../../src/modules/configPreset/import/configPreset-import-types';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';
import { ConfigImportMode } from '../../../../../src/modules/configImport/configImport-types';
import { plannedNamesOf } from '../../../../../src/modules/configPreset/registry/common-configPreset-registry';
import { importConfigPresetItem } from '../../../../../src/modules/configPreset/import/configPreset-import-engine';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const family = CONFIG_PRESET_FAMILIES.find(({ id }) => id === 'customViews')!;
const newPlan = (): ConfigPresetImportPlan => ({ created: new Set() });
const view = (name: string, targetEntityType = 'Report') => ({ name, target_entity_type: targetEntityType });
const item = (config: Record<string, unknown>, id = 'customview--1d6a8d3c-4f1c-4d35-8d0e-9b6b1a2c3d4e'): ConfigPresetBundleItem => ({
  type: 'customViews',
  id,
  path: `customization/custom_views/${id}.json`,
  configuration: config,
});
const computed = {} as ConfigPresetComputedItem;
const reservedNamesOf = (call: number) => vi.mocked(importCustomView).mock.calls[call][3].reservedNames;

beforeEach(() => {
  vi.resetAllMocks();
});

describe('Custom views import (registry)', () => {
  it('is importable, in the customization group, with a choice between overwriting the view of the name and adding a copy', () => {
    expect(family.importer).toBeDefined();
    expect(family.group.id).toBe('customization');
    // The custom views page of an entity type scopes the partial import to the entity type of the views
    expect(family.scopeKey).toBe('target_entity_type');
    expect(family.importModes).toEqual([ConfigImportMode.Overwrite, ConfigImportMode.Copy]);
  });

  it('computes the item with a dry run of the module, named by its trimmed name and its entity type', async () => {
    vi.mocked(importCustomView).mockResolvedValue({ status: 'overwritten', exists: true });
    const configuration = view(' Executive overview ', ' Report ');
    const result = await family.importer!.compute(context, user, item(configuration), newPlan(), ConfigImportMode.Overwrite);
    expect(importCustomView).toHaveBeenCalledWith(context, user, configuration, { mode: ConfigImportMode.Overwrite, dryRun: true, reservedNames: expect.any(Set) });
    expect(result).toMatchObject({ label: 'Executive overview (Report)', translatable: false, status: 'overwritten', exists: true, conflict: true });
  });

  it('does not check the id of the item against its content: a view is found by its entity type and its name', async () => {
    vi.mocked(importCustomView).mockResolvedValue({ status: 'created', exists: false });
    expect(await family.importer!.compute(context, user, item(view('Executive overview'), 'anything'), newPlan(), ConfigImportMode.Overwrite))
      .toMatchObject({ status: 'created', exists: false, conflict: false });
  });

  it('shares the names taken by the items of one plan, and starts empty with the next plan', async () => {
    vi.mocked(importCustomView).mockResolvedValue({ status: 'created', exists: false });
    const plan = newPlan();
    await family.importer!.compute(context, user, item(view('Executive overview')), plan, ConfigImportMode.Overwrite);
    await family.importer!.compute(context, user, item(view('Executive overview')), plan, ConfigImportMode.Overwrite);
    expect(reservedNamesOf(1)).toBe(reservedNamesOf(0));
    await family.importer!.compute(context, user, item(view('Executive overview')), newPlan(), ConfigImportMode.Overwrite);
    expect(reservedNamesOf(2)).not.toBe(reservedNamesOf(0));
  });

  it.each([[''], ['   '], [undefined], [42]])('leaves a blank or missing name (%j) to the module, which refuses it, and names the item by its id', async (name) => {
    vi.mocked(importCustomView).mockResolvedValue({ status: 'failed', code: 'invalid', reason: 'name: Invalid input', exists: false });
    expect(await family.importer!.compute(context, user, item({ name, target_entity_type: 'Report' }, 'customview--x'), newPlan(), ConfigImportMode.Overwrite))
      .toMatchObject({ status: 'failed', label: 'customview--x', reason: 'name: Invalid input' });
    expect(importCustomView).toHaveBeenCalledTimes(1);
  });

  it('names an item without entity type by its name alone', async () => {
    vi.mocked(importCustomView).mockResolvedValue({ status: 'failed', code: 'invalid', reason: 'target_entity_type: Invalid input', exists: false });
    expect(await family.importer!.compute(context, user, item({ name: 'Executive overview' }), newPlan(), ConfigImportMode.Overwrite))
      .toMatchObject({ status: 'failed', label: 'Executive overview' });
  });

  it('applies through the module without reserved names, reports a status that differs from the computed one, and throws on a failure', async () => {
    const configuration = view('Executive overview');
    vi.mocked(importCustomView).mockResolvedValueOnce({ status: 'created', exists: false });
    expect(await family.importer!.apply(context, user, item(configuration), { ...computed, status: 'created' }, ConfigImportMode.Overwrite, newPlan())).toBeUndefined();
    expect(importCustomView).toHaveBeenCalledWith(context, user, configuration, { mode: ConfigImportMode.Overwrite });
    vi.mocked(importCustomView).mockResolvedValueOnce({ status: 'skipped', code: 'unchanged', exists: true, reason: 'Already up to date' });
    expect(await family.importer!.apply(context, user, item(configuration), { ...computed, status: 'overwritten' }, ConfigImportMode.Overwrite, newPlan()))
      .toEqual({ status: 'skipped', reason: 'Already up to date' });
    vi.mocked(importCustomView).mockResolvedValueOnce({ status: 'failed', code: 'exists', reason: 'Custom view already exists', exists: true });
    await expect(family.importer!.apply(context, user, item(configuration), { ...computed, status: 'created' }, ConfigImportMode.Add, newPlan())).rejects.toThrow('Custom view already exists');
  });
});

// The engine computes an item (a dry run on the plan) then writes it, item after item on one plan. The module is replaced by a platform that
// keeps the names written, and decides as the module does with the names of the plan: only the wiring of the registry and the engine is checked here,
// the decisions of the module are the ones of its own tests
describe('Custom views import (real import through the engine)', () => {
  const written: string[] = [];
  beforeEach(() => {
    written.length = 0;
    vi.mocked(importCustomView).mockImplementation(async (_context, _user, configuration, { mode, dryRun, reservedNames }) => {
      const { name, target_entity_type: type } = configuration as { name: string; target_entity_type: string };
      const key = `${type}/${name}`;
      if (mode === ConfigImportMode.Overwrite && reservedNames?.has(key)) {
        return { status: 'failed', code: 'duplicate', reason: 'Another custom view of the import has this name', exists: false };
      }
      if (dryRun) {
        reservedNames?.add(key);
      } else {
        written.push(key);
      }
      return { status: 'created', exists: false };
    });
  });

  it('refuses the second view of a name and an entity type without writing it, and writes the first', async () => {
    const plan = newPlan();
    const first = await importConfigPresetItem(context, user, item(view('Executive overview'), 'customview--a'), plan, ConfigImportMode.Overwrite);
    const second = await importConfigPresetItem(context, user, item(view('Executive overview'), 'customview--b'), plan, ConfigImportMode.Overwrite);
    expect(first.status).toBe('CREATED');
    expect(second).toMatchObject({ status: 'FAILED', reason: 'Another custom view of the import has this name' });
    expect(written).toEqual(['Report/Executive overview']);
  });

  it('writes a view of the same name on another entity type, and in a later import', async () => {
    const plan = newPlan();
    await importConfigPresetItem(context, user, item(view('Overview'), 'customview--a'), plan, ConfigImportMode.Overwrite);
    expect((await importConfigPresetItem(context, user, item(view('Overview', 'Malware'), 'customview--b'), plan, ConfigImportMode.Overwrite)).status).toBe('CREATED');
    // A new import has its own plan: the names of the previous one are free
    expect((await importConfigPresetItem(context, user, item(view('Overview'), 'customview--c'), newPlan(), ConfigImportMode.Overwrite)).status).toBe('CREATED');
    expect(written).toEqual(['Report/Overview', 'Malware/Overview', 'Report/Overview']);
  });

  it('keeps its names apart from the ones another family reserves in the same plan', async () => {
    vi.mocked(importCustomView).mockResolvedValue({ status: 'created', exists: false });
    const plan = newPlan();
    await family.importer!.compute(context, user, item(view('Overview')), plan, ConfigImportMode.Overwrite);
    expect(reservedNamesOf(0)).not.toBe(plannedNamesOf(plan, 'dashboards'));
    expect(plannedNamesOf(plan, 'dashboards')).toBe(plannedNamesOf(plan, 'dashboards'));
  });

  it('computes each item with the names of the plan, and writes it with none: the platform decides from what it holds', async () => {
    const plan = newPlan();
    await importConfigPresetItem(context, user, item(view('Overview'), 'customview--a'), plan, ConfigImportMode.Copy);
    await importConfigPresetItem(context, user, item(view('Overview'), 'customview--b'), plan, ConfigImportMode.Copy);
    const options = vi.mocked(importCustomView).mock.calls.map(([, , , option]) => option);
    // compute, write, compute, write
    expect(options.map(({ dryRun }) => !!dryRun)).toEqual([true, false, true, false]);
    expect(options[0].reservedNames).toBe(options[2].reservedNames);
    expect(options[1].reservedNames).toBeUndefined();
    expect(options[3].reservedNames).toBeUndefined();
  });

  it('writes nothing for an item the module refuses, and tells why', async () => {
    vi.mocked(importCustomView).mockResolvedValue({ status: 'failed', code: 'entity_type', reason: 'Custom views cannot be created for this entity type', exists: false });
    const result = await importConfigPresetItem(context, user, item(view('Overview', 'Note')), newPlan(), ConfigImportMode.Overwrite);
    expect(result).toMatchObject({ status: 'FAILED', reason: 'Custom views cannot be created for this entity type' });
    expect(vi.mocked(importCustomView).mock.calls.filter(([, , , options]) => !options.dryRun)).toHaveLength(0);
  });
});
