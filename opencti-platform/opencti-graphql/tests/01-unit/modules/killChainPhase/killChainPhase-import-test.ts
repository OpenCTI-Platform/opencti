import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  storeLoadById: vi.fn(),
}));
vi.mock('../../../../src/domain/killChainPhase', () => ({ addKillChainPhase: vi.fn(), killChainPhaseEditField: vi.fn() }));

import { storeLoadById } from '../../../../src/database/middleware-loader';
import { addKillChainPhase, killChainPhaseEditField } from '../../../../src/domain/killChainPhase';
import { ENTITY_TYPE_KILL_CHAIN_PHASE } from '../../../../src/schema/stixMetaObject';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import { getKillChainPhaseStandardId, importKillChainPhase } from '../../../../src/modules/killChainPhase/killChainPhase-import';
import { killChainPhaseImportSchema } from '../../../../src/modules/killChainPhase/killChainPhase-import-schema';
import { getKillChainPhaseConfigPresetConfiguration } from '../../../../src/modules/killChainPhase/killChainPhase-export';
import type { BasicStoreEntityKillChainPhase } from '../../../../src/modules/killChainPhase/killChainPhase-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const names = { kill_chain_name: 'mitre-attack', phase_name: 'execution' };
const stored = { id: 'phase-internal-id', standard_id: getKillChainPhaseStandardId(names), ...names, x_opencti_order: 2 } as BasicStoreEntityKillChainPhase;

const withExisting = (phase?: BasicStoreEntityKillChainPhase) => vi.mocked(storeLoadById).mockResolvedValue(phase as never);

beforeEach(() => {
  vi.resetAllMocks();
  withExisting(undefined);
});

describe('Kill chain phase identity', () => {
  it('derives the standard id from the two names, ignoring surrounding spaces but not the case', () => {
    expect(getKillChainPhaseStandardId(names)).toMatch(/^kill-chain-phase--[0-9a-f-]{36}$/);
    expect(getKillChainPhaseStandardId({ kill_chain_name: ' mitre-attack ', phase_name: 'execution ' })).toBe(getKillChainPhaseStandardId(names));
    // The platform does not fold the case of a phase: Execution is another phase
    expect(getKillChainPhaseStandardId({ ...names, phase_name: 'Execution' })).not.toBe(getKillChainPhaseStandardId(names));
    expect(getKillChainPhaseStandardId({ ...names, kill_chain_name: 'disarm' })).not.toBe(getKillChainPhaseStandardId(names));
  });
});

describe('Kill chain phase import schema', () => {
  it('accepts the two names with or without an order, and trims the names', () => {
    expect(killChainPhaseImportSchema.parse({ kill_chain_name: ' mitre-attack ', phase_name: 'execution', x_opencti_order: 0 })).toEqual({ ...names, x_opencti_order: 0 });
    expect(killChainPhaseImportSchema.parse(names)).toEqual(names);
    expect(killChainPhaseImportSchema.parse({ ...names, x_opencti_order: null })).toEqual({ ...names, x_opencti_order: null });
  });

  it.each([
    [{}],
    [{ phase_name: 'execution' }],
    [{ kill_chain_name: 'mitre-attack' }],
    [{ kill_chain_name: '  ', phase_name: 'execution' }],
    [{ ...names, x_opencti_order: 1.5 }],
    [{ ...names, x_opencti_order: '2' }],
    [{ ...names, standard_id: 'kill-chain-phase--x' }],
  ])('refuses %j', (configuration) => {
    expect(killChainPhaseImportSchema.safeParse(configuration).success).toBe(false);
  });

  it('is the format of the export, so an export imports back as is, an order of 0 included', () => {
    const configuration = getKillChainPhaseConfigPresetConfiguration({ ...stored, x_opencti_order: 0, creator_id: ['secret'] } as BasicStoreEntityKillChainPhase);
    expect(configuration).toEqual({ ...names, x_opencti_order: 0 });
    expect(killChainPhaseImportSchema.safeParse(configuration).success).toBe(true);
  });
});

describe('importKillChainPhase', () => {
  it('refuses an invalid configuration with the path of each issue, without reading the platform', async () => {
    const result = await importKillChainPhase(context, user, { kill_chain_name: '', x_opencti_order: 'one' }, { mode: ConfigImportMode.Overwrite });
    expect(result).toMatchObject({ status: 'failed', code: 'invalid', exists: false });
    expect(result.reason).toContain('kill_chain_name: Kill chain name is required');
    expect(result.reason).toContain('phase_name');
    expect(result.reason).toContain('x_opencti_order');
    expect(storeLoadById).not.toHaveBeenCalled();
  });

  it('finds the phase by its standard id', async () => {
    await importKillChainPhase(context, user, names, { mode: ConfigImportMode.Overwrite, dryRun: true });
    expect(storeLoadById).toHaveBeenCalledWith(context, user, getKillChainPhaseStandardId(names), ENTITY_TYPE_KILL_CHAIN_PHASE);
  });

  describe.each([ConfigImportMode.Overwrite, ConfigImportMode.Add])('a phase that does not exist (%s)', (mode) => {
    it('creates it with the given order', async () => {
      expect(await importKillChainPhase(context, user, { ...names, x_opencti_order: 3 }, { mode })).toMatchObject({ status: 'created', exists: false });
      expect(addKillChainPhase).toHaveBeenCalledWith(context, user, { ...names, x_opencti_order: 3 });
    });

    it('gives it the order 0 when the configuration has none, and keeps an order of 0', async () => {
      await importKillChainPhase(context, user, names, { mode });
      expect(addKillChainPhase).toHaveBeenLastCalledWith(context, user, { ...names, x_opencti_order: 0 });
      await importKillChainPhase(context, user, { ...names, x_opencti_order: null }, { mode });
      expect(addKillChainPhase).toHaveBeenLastCalledWith(context, user, { ...names, x_opencti_order: 0 });
    });

    it('decides the same result on a dry run, and writes nothing', async () => {
      expect(await importKillChainPhase(context, user, names, { mode, dryRun: true })).toMatchObject({ status: 'created', exists: false });
      expect(addKillChainPhase).not.toHaveBeenCalled();
    });
  });

  describe('a phase that exists, overwrite', () => {
    beforeEach(() => withExisting(stored));

    it('gives it the order of the configuration', async () => {
      expect(await importKillChainPhase(context, user, { ...names, x_opencti_order: 5 }, { mode: ConfigImportMode.Overwrite })).toMatchObject({ status: 'overwritten', exists: true });
      expect(killChainPhaseEditField).toHaveBeenCalledWith(context, user, stored.id, [{ key: 'x_opencti_order', value: [5] }]);
      expect(addKillChainPhase).not.toHaveBeenCalled();
    });

    it('gives it the order 0, which is an order and not an absent one', async () => {
      expect(await importKillChainPhase(context, user, { ...names, x_opencti_order: 0 }, { mode: ConfigImportMode.Overwrite })).toMatchObject({ status: 'overwritten' });
      expect(killChainPhaseEditField).toHaveBeenCalledWith(context, user, stored.id, [{ key: 'x_opencti_order', value: [0] }]);
    });

    it('writes nothing on a dry run', async () => {
      expect(await importKillChainPhase(context, user, { ...names, x_opencti_order: 5 }, { mode: ConfigImportMode.Overwrite, dryRun: true })).toMatchObject({ status: 'overwritten', exists: true });
      expect(killChainPhaseEditField).not.toHaveBeenCalled();
    });

    it.each([
      ['has the same order', { ...names, x_opencti_order: 2 }],
      ['has no order', names],
      ['has a null order', { ...names, x_opencti_order: null }],
    ])('skips it when the configuration %s', async (_name, configuration) => {
      expect(await importKillChainPhase(context, user, configuration, { mode: ConfigImportMode.Overwrite })).toMatchObject({ status: 'skipped', code: 'unchanged', exists: true, reason: 'Nothing to import' });
      expect(killChainPhaseEditField).not.toHaveBeenCalled();
    });
  });

  it('refuses a phase that exists when the mode is add', async () => {
    withExisting(stored);
    expect(await importKillChainPhase(context, user, { ...names, x_opencti_order: 5 }, { mode: ConfigImportMode.Add })).toMatchObject({ status: 'failed', code: 'exists', exists: true });
    expect(killChainPhaseEditField).not.toHaveBeenCalled();
  });

  it('has no copy: a phase is its names', async () => {
    withExisting(stored);
    expect(await importKillChainPhase(context, user, names, { mode: ConfigImportMode.Copy })).toMatchObject({ status: 'failed', code: 'copy_unsupported', exists: true });
    withExisting(undefined);
    expect(await importKillChainPhase(context, user, names, { mode: ConfigImportMode.Copy })).toMatchObject({ status: 'failed', code: 'copy_unsupported', exists: false });
    expect(addKillChainPhase).not.toHaveBeenCalled();
    expect(killChainPhaseEditField).not.toHaveBeenCalled();
  });
});
