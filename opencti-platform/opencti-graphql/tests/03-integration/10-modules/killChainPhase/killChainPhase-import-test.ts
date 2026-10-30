import { afterAll, describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { findAllKillChainPhases, killChainPhaseDelete } from '../../../../src/domain/killChainPhase';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import { getKillChainPhaseStandardId, importKillChainPhase } from '../../../../src/modules/killChainPhase/killChainPhase-import';
import { killChainPhasesFamily } from '../../../../src/modules/configPreset/registry/killChainPhases-configPreset-registry';
import { exportConfigPresetItem } from '../../../../src/modules/configPreset/configPreset-registry';
import { storeLoadById } from '../../../../src/database/middleware-loader';
import { ENTITY_TYPE_KILL_CHAIN_PHASE } from '../../../../src/schema/stixMetaObject';

const CHAIN = 'config-preset-chain';
const PHASE_A = { kill_chain_name: CHAIN, phase_name: 'Phase A' };
const PHASE_B = { kill_chain_name: CHAIN, phase_name: 'Phase B' };
const idA = getKillChainPhaseStandardId(PHASE_A);
const idB = getKillChainPhaseStandardId(PHASE_B);
const mode = ConfigImportMode.Overwrite;
const load = (id: string) => storeLoadById(testContext, ADMIN_USER, id, ENTITY_TYPE_KILL_CHAIN_PHASE);

describe('Kill chain phase import and export (configuration preset)', () => {
  afterAll(async () => {
    for (const id of [idA, idB]) {
      const phase = await load(id);
      if (phase) {
        await killChainPhaseDelete(testContext, ADMIN_USER, phase.id);
      }
    }
  });

  it('writes nothing on a dry run, and creates the phase otherwise, with the order 0 by default', async () => {
    expect(await importKillChainPhase(testContext, ADMIN_USER, { ...PHASE_A, x_opencti_order: 4 }, { mode, dryRun: true })).toMatchObject({ status: 'created', exists: false });
    expect(await load(idA)).toBeFalsy();
    expect(await importKillChainPhase(testContext, ADMIN_USER, { ...PHASE_A, x_opencti_order: 4 }, { mode })).toMatchObject({ status: 'created', exists: false });
    expect(await load(idA)).toMatchObject({ ...PHASE_A, x_opencti_order: 4 });
    expect(await importKillChainPhase(testContext, ADMIN_USER, PHASE_B, { mode })).toMatchObject({ status: 'created' });
    expect(await load(idB)).toMatchObject({ ...PHASE_B, x_opencti_order: 0 });
  });

  it('never duplicates a phase: an import of the same names skips it or overwrites its order', async () => {
    expect(await importKillChainPhase(testContext, ADMIN_USER, { ...PHASE_A, x_opencti_order: 4 }, { mode })).toMatchObject({ status: 'skipped', code: 'unchanged', exists: true });
    expect(await importKillChainPhase(testContext, ADMIN_USER, PHASE_A, { mode })).toMatchObject({ status: 'skipped', code: 'unchanged', exists: true });
    expect(await importKillChainPhase(testContext, ADMIN_USER, { ...PHASE_A, x_opencti_order: 4 }, { mode: ConfigImportMode.Add })).toMatchObject({ status: 'failed', code: 'exists' });
    expect(await importKillChainPhase(testContext, ADMIN_USER, { ...PHASE_A, x_opencti_order: 7 }, { mode, dryRun: true })).toMatchObject({ status: 'overwritten', exists: true });
    expect(await load(idA)).toMatchObject({ x_opencti_order: 4 });
    expect(await importKillChainPhase(testContext, ADMIN_USER, { ...PHASE_A, x_opencti_order: 7 }, { mode })).toMatchObject({ status: 'overwritten', exists: true });
    expect(await load(idA)).toMatchObject({ x_opencti_order: 7 });
    // An order of 0 is an order
    expect(await importKillChainPhase(testContext, ADMIN_USER, { ...PHASE_A, x_opencti_order: 0 }, { mode })).toMatchObject({ status: 'overwritten', exists: true });
    expect(await load(idA)).toMatchObject({ x_opencti_order: 0 });
    expect(await findAllKillChainPhases(testContext, ADMIN_USER, { filters: { mode: 'and', filters: [{ key: ['kill_chain_name'], values: [CHAIN] }], filterGroups: [] } })).toHaveLength(2);
  });

  it('does not fold the case of a phase: another case is another phase', async () => {
    const lower = { kill_chain_name: CHAIN, phase_name: 'phase a' };
    expect(getKillChainPhaseStandardId(lower)).not.toBe(idA);
    expect(await importKillChainPhase(testContext, ADMIN_USER, lower, { mode, dryRun: true })).toMatchObject({ status: 'created', exists: false });
  });

  it('lists, searches and resolves the phases through the family, by kill chain then by order', async () => {
    await importKillChainPhase(testContext, ADMIN_USER, { ...PHASE_A, x_opencti_order: 9 }, { mode });
    const page = await killChainPhasesFamily.listItems(testContext, ADMIN_USER, { first: 10, search: CHAIN });
    expect(page.edges.map(({ node }) => [node.id, node.label, node.translatable])).toEqual([
      [idB, `${CHAIN}: Phase B`, false],
      [idA, `${CHAIN}: Phase A`, false],
    ]);
    expect(page.pageInfo.globalCount).toBe(2);
    expect((await killChainPhasesFamily.listItems(testContext, ADMIN_USER, { ids: [idB] })).edges.map(({ node }) => node.id)).toEqual([idB]);
    expect((await killChainPhasesFamily.listItems(testContext, ADMIN_USER, { ids: [] })).edges).toEqual([]);
    expect((await killChainPhasesFamily.resolveItems(testContext, ADMIN_USER, [idA, idB], [idA])).map(({ id }) => id)).toEqual([idB]);
    expect((await killChainPhasesFamily.resolveItems(testContext, ADMIN_USER, [], [])).map(({ id }) => id)).toEqual([]);
  });

  it('imports an export back, whatever the platform it comes from', async () => {
    const [item] = await killChainPhasesFamily.resolveItems(testContext, ADMIN_USER, [idB], []);
    const file = await exportConfigPresetItem(testContext, ADMIN_USER, killChainPhasesFamily, item);
    expect(file).toMatchObject({ type: 'taxonomy.killChainPhases', id: idB, configuration: { ...PHASE_B, x_opencti_order: 0 } });
    await killChainPhaseDelete(testContext, ADMIN_USER, (await load(idB)).id);
    expect(await importKillChainPhase(testContext, ADMIN_USER, file.configuration, { mode })).toMatchObject({ status: 'created', exists: false });
    expect(await load(idB)).toMatchObject({ ...PHASE_B, x_opencti_order: 0 });
  });
});
