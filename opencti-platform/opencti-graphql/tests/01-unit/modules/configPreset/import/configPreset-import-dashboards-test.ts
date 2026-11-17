import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../../src/modules/workspace/workspace-import', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/modules/workspace/workspace-import')>()),
  importDashboard: vi.fn(),
}));

import { importDashboard } from '../../../../../src/modules/workspace/workspace-import';
import { CONFIG_PRESET_FAMILIES } from '../../../../../src/modules/configPreset/configPreset-registry';
import type { ConfigPresetBundleItem, ConfigPresetComputedItem, ConfigPresetImportPlan } from '../../../../../src/modules/configPreset/import/configPreset-import-types';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';
import { ConfigImportMode } from '../../../../../src/modules/configImport/configImport-types';
import { importConfigPresetItem } from '../../../../../src/modules/configPreset/import/configPreset-import-engine';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const family = CONFIG_PRESET_FAMILIES.find(({ id }) => id === 'dashboards')!;
const newPlan = (): ConfigPresetImportPlan => ({ created: new Set() });
const item = (config: Record<string, unknown>, id = 'workspace--1d6a8d3c-4f1c-4d35-8d0e-9b6b1a2c3d4e'): ConfigPresetBundleItem => ({ type: 'dashboards', id, path: `dashboards/${id}.json`, configuration: config });
const computed = {} as ConfigPresetComputedItem;
const reservedNamesOf = (call: number) => vi.mocked(importDashboard).mock.calls[call][3].reservedNames;

beforeEach(() => {
  vi.resetAllMocks();
});

describe('Dashboards import (registry)', () => {
  it('is importable, with a choice between overwriting the dashboard of the name and adding a copy', () => {
    expect(family.importer).toBeDefined();
    expect(family.importModes).toEqual([ConfigImportMode.Overwrite, ConfigImportMode.Copy]);
  });

  it('computes the item with a dry run of the module, named by its trimmed name', async () => {
    vi.mocked(importDashboard).mockResolvedValue({ status: 'overwritten', exists: true });
    const result = await family.importer!.compute(context, user, item({ name: ' SOC overview ' }), newPlan(), ConfigImportMode.Overwrite);
    expect(importDashboard).toHaveBeenCalledWith(context, user, { name: ' SOC overview ' }, { mode: ConfigImportMode.Overwrite, dryRun: true, reservedNames: expect.any(Set) });
    expect(result).toMatchObject({ label: 'SOC overview', translatable: false, status: 'overwritten', exists: true, conflict: true });
  });

  it('does not check the id of the item against its content: a dashboard is found by its name', async () => {
    vi.mocked(importDashboard).mockResolvedValue({ status: 'created', exists: false });
    expect(await family.importer!.compute(context, user, item({ name: 'SOC overview' }, 'anything'), newPlan(), ConfigImportMode.Overwrite))
      .toMatchObject({ status: 'created', exists: false, conflict: false });
  });

  it('shares the names taken by the items of one plan, and starts empty with the next plan', async () => {
    vi.mocked(importDashboard).mockResolvedValue({ status: 'created', exists: false });
    const plan = newPlan();
    await family.importer!.compute(context, user, item({ name: 'SOC overview' }), plan, ConfigImportMode.Overwrite);
    await family.importer!.compute(context, user, item({ name: 'SOC overview' }), plan, ConfigImportMode.Overwrite);
    expect(reservedNamesOf(1)).toBe(reservedNamesOf(0));
    await family.importer!.compute(context, user, item({ name: 'SOC overview' }), newPlan(), ConfigImportMode.Overwrite);
    expect(reservedNamesOf(2)).not.toBe(reservedNamesOf(0));
  });

  it.each([[''], ['   '], [undefined], [42]])('leaves a blank or missing name (%j) to the module, which refuses it, and names the item by its id', async (name) => {
    vi.mocked(importDashboard).mockResolvedValue({ status: 'failed', code: 'invalid', reason: 'name: Invalid input', exists: false });
    expect(await family.importer!.compute(context, user, item({ name }, 'workspace--x'), newPlan(), ConfigImportMode.Overwrite))
      .toMatchObject({ status: 'failed', label: 'workspace--x', reason: 'name: Invalid input' });
    expect(importDashboard).toHaveBeenCalledTimes(1);
  });

  it('applies through the module without reserved names, reports a status that differs from the computed one, and throws on a failure', async () => {
    const configuration = { name: 'SOC overview' };
    vi.mocked(importDashboard).mockResolvedValueOnce({ status: 'created', exists: false });
    expect(await family.importer!.apply(context, user, item(configuration), { ...computed, status: 'created' }, ConfigImportMode.Overwrite, newPlan())).toBeUndefined();
    expect(importDashboard).toHaveBeenCalledWith(context, user, configuration, { mode: ConfigImportMode.Overwrite });
    vi.mocked(importDashboard).mockResolvedValueOnce({ status: 'skipped', code: 'unchanged', exists: true, reason: 'Already up to date' });
    expect(await family.importer!.apply(context, user, item(configuration), { ...computed, status: 'overwritten' }, ConfigImportMode.Overwrite, newPlan()))
      .toEqual({ status: 'skipped', reason: 'Already up to date' });
    vi.mocked(importDashboard).mockResolvedValueOnce({ status: 'failed', code: 'exists', reason: 'Dashboard already exists', exists: true });
    await expect(family.importer!.apply(context, user, item(configuration), { ...computed, status: 'created' }, ConfigImportMode.Add, newPlan())).rejects.toThrow('Dashboard already exists');
  });
});

// The engine computes an item (a dry run on the plan) then writes it, item after item on one plan. The module is replaced by a platform that
// keeps the names written, and decides as the module does with the names of the plan: only the wiring of the registry and the engine is checked here,
// the decisions of the module are the ones of the integration tests
describe('Dashboards import (real import through the engine)', () => {
  const written: string[] = [];
  beforeEach(() => {
    written.length = 0;
    vi.mocked(importDashboard).mockImplementation(async (_context, _user, configuration, { mode, dryRun, reservedNames }) => {
      const { name } = configuration as { name: string };
      if (mode === ConfigImportMode.Overwrite && reservedNames?.has(name)) {
        return { status: 'failed', code: 'duplicate', reason: 'Another dashboard of the import has this name', exists: false };
      }
      if (dryRun) {
        reservedNames?.add(name);
      } else {
        written.push(name);
      }
      return { status: 'created', exists: false };
    });
  });
  const writes = () => vi.mocked(importDashboard).mock.calls.filter(([, , , options]) => !options.dryRun);

  it('refuses the second dashboard of a name without writing it, and writes the first', async () => {
    const plan = newPlan();
    const first = await importConfigPresetItem(context, user, item({ name: 'SOC overview' }, 'workspace--a'), plan, ConfigImportMode.Overwrite);
    const second = await importConfigPresetItem(context, user, item({ name: 'SOC overview' }, 'workspace--b'), plan, ConfigImportMode.Overwrite);
    expect(first.status).toBe('CREATED');
    expect(second).toMatchObject({ status: 'FAILED', reason: 'Another dashboard of the import has this name' });
    expect(written).toEqual(['SOC overview']);
    expect(writes()).toHaveLength(1);
  });

  it('writes a dashboard of another name, and a dashboard of the same name in a later import', async () => {
    const plan = newPlan();
    await importConfigPresetItem(context, user, item({ name: 'SOC overview' }, 'workspace--a'), plan, ConfigImportMode.Overwrite);
    expect((await importConfigPresetItem(context, user, item({ name: 'Executive summary' }, 'workspace--b'), plan, ConfigImportMode.Overwrite)).status).toBe('CREATED');
    // A new import has its own plan: the names of the previous one are free
    expect((await importConfigPresetItem(context, user, item({ name: 'SOC overview' }, 'workspace--c'), newPlan(), ConfigImportMode.Overwrite)).status).toBe('CREATED');
    expect(written).toEqual(['SOC overview', 'Executive summary', 'SOC overview']);
  });

  it('computes each item with the names of the plan, and writes it with none: the platform decides from what it holds', async () => {
    const plan = newPlan();
    await importConfigPresetItem(context, user, item({ name: 'SOC overview' }, 'workspace--a'), plan, ConfigImportMode.Copy);
    await importConfigPresetItem(context, user, item({ name: 'SOC overview' }, 'workspace--b'), plan, ConfigImportMode.Copy);
    const options = vi.mocked(importDashboard).mock.calls.map(([, , , option]) => option);
    // compute, write, compute, write
    expect(options.map(({ dryRun }) => !!dryRun)).toEqual([true, false, true, false]);
    expect(options[0].reservedNames).toBe(options[2].reservedNames);
    expect(options[1].reservedNames).toBeUndefined();
    expect(options[3].reservedNames).toBeUndefined();
  });

  it('writes nothing for an item the module refuses, and tells why', async () => {
    vi.mocked(importDashboard).mockResolvedValue({ status: 'failed', code: 'ambiguous', reason: 'Several dashboards have this name', exists: true });
    const result = await importConfigPresetItem(context, user, item({ name: 'SOC overview' }), newPlan(), ConfigImportMode.Overwrite);
    expect(result).toMatchObject({ status: 'FAILED', reason: 'Several dashboards have this name' });
    expect(writes()).toHaveLength(0);
  });

  it('fails the item whose write fails, and goes on with the next one', async () => {
    const plan = newPlan();
    vi.mocked(importDashboard).mockImplementation(async (_context, _user, _configuration, { dryRun }) => {
      if (!dryRun) throw new Error('Write failed');
      return { status: 'created', exists: false };
    });
    expect(await importConfigPresetItem(context, user, item({ name: 'SOC overview' }, 'workspace--a'), plan, ConfigImportMode.Overwrite))
      .toMatchObject({ status: 'FAILED', reason: 'Write failed' });
    vi.mocked(importDashboard).mockResolvedValue({ status: 'created', exists: false });
    expect((await importConfigPresetItem(context, user, item({ name: 'Executive summary' }, 'workspace--b'), plan, ConfigImportMode.Overwrite)).status).toBe('CREATED');
  });
});
