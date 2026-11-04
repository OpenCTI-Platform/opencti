import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../../src/modules/killChainPhase/killChainPhase-import', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/modules/killChainPhase/killChainPhase-import')>()),
  importKillChainPhase: vi.fn(),
}));

import { getKillChainPhaseStandardId, importKillChainPhase } from '../../../../../src/modules/killChainPhase/killChainPhase-import';
import { CONFIG_PRESET_FAMILIES } from '../../../../../src/modules/configPreset/configPreset-registry';
import type { ConfigPresetBundleItem, ConfigPresetComputedItem, ConfigPresetImportPlan } from '../../../../../src/modules/configPreset/import/configPreset-import-types';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';
import { ConfigImportMode } from '../../../../../src/modules/configImport/configImport-types';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const family = CONFIG_PRESET_FAMILIES.find(({ id }) => id === 'killChainPhases')!;
const plan: ConfigPresetImportPlan = { created: new Set() };
const names = { kill_chain_name: 'mitre-attack', phase_name: 'execution' };
const phaseId = getKillChainPhaseStandardId(names);
const item = (configuration: Record<string, unknown>, id = phaseId): ConfigPresetBundleItem => ({ type: 'killChainPhases', id, path: `taxonomy/kill_chain_phases/${id}.json`, configuration });
const computed = {} as ConfigPresetComputedItem;

beforeEach(() => {
  vi.resetAllMocks();
});

describe('Kill chain phases import (registry)', () => {
  it('is importable and offers no choice of mode: a phase has no copy', () => {
    expect(family.importer).toBeDefined();
    expect(family.importModes).toBeUndefined();
  });

  it('computes the item with a dry run of the module, named by its two names', async () => {
    vi.mocked(importKillChainPhase).mockResolvedValue({ status: 'overwritten', exists: true });
    const configuration = { ...names, x_opencti_order: 2 };
    const result = await family.importer!.compute(context, user, item(configuration), plan, ConfigImportMode.Overwrite);
    expect(importKillChainPhase).toHaveBeenCalledWith(context, user, configuration, { mode: ConfigImportMode.Overwrite, dryRun: true });
    expect(result).toMatchObject({ label: 'mitre-attack: execution', translatable: false, status: 'overwritten', exists: true, conflict: true });
  });

  it('accepts an id computed from the names with their surrounding spaces trimmed, as the platform does', async () => {
    vi.mocked(importKillChainPhase).mockResolvedValue({ status: 'created', exists: false });
    const result = await family.importer!.compute(context, user, item({ kill_chain_name: ' mitre-attack', phase_name: 'execution ' }), plan, ConfigImportMode.Overwrite);
    expect(result).toMatchObject({ label: 'mitre-attack: execution', status: 'created', exists: false, conflict: false });
  });

  it('fails an item whose id is not the standard id of its names, without asking the module', async () => {
    const result = await family.importer!.compute(context, user, item(names, getKillChainPhaseStandardId({ ...names, phase_name: 'Execution' })), plan, ConfigImportMode.Overwrite);
    expect(result).toMatchObject({ status: 'failed', label: 'mitre-attack: execution', reason: 'The standard id of the kill chain phase does not match its names' });
    expect(importKillChainPhase).not.toHaveBeenCalled();
  });

  it('leaves a configuration without names to the module, which refuses it, and names the item by its id', async () => {
    vi.mocked(importKillChainPhase).mockResolvedValue({ status: 'failed', code: 'invalid', reason: 'phase_name: Invalid input', exists: false });
    expect(await family.importer!.compute(context, user, item({ kill_chain_name: 'mitre-attack' }), plan, ConfigImportMode.Overwrite))
      .toMatchObject({ status: 'failed', label: phaseId, reason: 'phase_name: Invalid input' });
  });

  it.each([
    ['kill chain name', { kill_chain_name: '  ', phase_name: 'execution' }],
    ['phase name', { kill_chain_name: 'mitre-attack', phase_name: '' }],
  ])('leaves a blank %s to the module, which refuses it: the standard id of a blank name cannot be derived', async (_name, configuration) => {
    vi.mocked(importKillChainPhase).mockResolvedValue({ status: 'failed', code: 'invalid', reason: 'Name is required', exists: false });
    expect(await family.importer!.compute(context, user, item(configuration), plan, ConfigImportMode.Overwrite)).toMatchObject({ status: 'failed', reason: 'Name is required' });
    expect(importKillChainPhase).toHaveBeenCalled();
  });

  it('applies through the module, reports a status that differs from the computed one, and throws on a failure', async () => {
    const configuration = { ...names, x_opencti_order: 2 };
    vi.mocked(importKillChainPhase).mockResolvedValueOnce({ status: 'created', exists: false });
    expect(await family.importer!.apply(context, user, item(configuration), { ...computed, status: 'created' }, ConfigImportMode.Overwrite)).toBeUndefined();
    expect(importKillChainPhase).toHaveBeenCalledWith(context, user, configuration, { mode: ConfigImportMode.Overwrite });
    vi.mocked(importKillChainPhase).mockResolvedValueOnce({ status: 'skipped', code: 'unchanged', exists: true });
    expect(await family.importer!.apply(context, user, item(configuration), { ...computed, status: 'created' }, ConfigImportMode.Overwrite)).toBe('skipped');
    vi.mocked(importKillChainPhase).mockResolvedValueOnce({ status: 'failed', code: 'invalid', reason: 'phase_name: Invalid input', exists: false });
    await expect(family.importer!.apply(context, user, item(configuration), { ...computed, status: 'created' }, ConfigImportMode.Overwrite)).rejects.toThrow('phase_name: Invalid input');
  });
});
