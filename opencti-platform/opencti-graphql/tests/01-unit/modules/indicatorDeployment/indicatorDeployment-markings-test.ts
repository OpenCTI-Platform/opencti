import { describe, expect, it, vi } from 'vitest';

import '../../../../src/modules/index';
import { expectedPairMarkings } from '../../../../src/modules/indicatorDeployment/indicatorDeployment-domain';
import { keepsPairMarkings, markingsAfterEdits } from '../../../../src/modules/iocValidation/iocValidation-validator';
import { getEntityValidatorUpdate, type ValidatorFn } from '../../../../src/schema/validator-register';
import { RELATION_DEPLOYED_ON } from '../../../../src/modules/indicatorDeployment/indicatorDeployment-types';
import { EditOperation } from '../../../../src/generated/graphql';
import type { AuthUser } from '../../../../src/types/user';
import { testContext } from '../../../utils/testQuery';

// Marking definitions of the platform cache, reachable by internal id and by standard id.
const MARKINGS = [
  { internal_id: 'tlp-green', standard_id: 'marking-definition--tlp-green', definition_type: 'TLP', x_opencti_order: 2 },
  { internal_id: 'tlp-amber', standard_id: 'marking-definition--tlp-amber', definition_type: 'TLP', x_opencti_order: 3 },
  { internal_id: 'tlp-red', standard_id: 'marking-definition--tlp-red', definition_type: 'TLP', x_opencti_order: 4 },
  { internal_id: 'pap-red', standard_id: 'marking-definition--pap-red', definition_type: 'PAP', x_opencti_order: 4 },
  { internal_id: 'statement-1', standard_id: 'marking-definition--statement-1', definition_type: 'statement', x_opencti_order: 1 },
];
vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/cache')>()),
  getEntitiesMapFromCache: async () => new Map(MARKINGS.flatMap((marking) => [[marking.internal_id, marking], [marking.standard_id, marking]])),
}));

const ends = (indicator: string[], platform: string[]) => [{ 'object-marking': indicator }, { 'object-marking': platform }] as const;
const sorted = (ids: string[]) => [...ids].sort();

describe('markings of a pair relationship', () => {
  it('should follow an end that relaxes its marking', async () => {
    const [indicator, platform] = ends(['tlp-green'], ['tlp-green']);
    expect(await expectedPairMarkings(testContext, ['tlp-red'], indicator, platform)).toEqual(['tlp-green']);
  });

  it('should keep the highest marking of a type among the ends', async () => {
    const [indicator, platform] = ends(['tlp-green'], ['tlp-red']);
    expect(await expectedPairMarkings(testContext, ['tlp-red'], indicator, platform)).toEqual(['tlp-red']);
    expect(await expectedPairMarkings(testContext, [], indicator, platform)).toEqual(['tlp-red']);
  });

  it('should keep a marking of a type neither end carries, set on the relationship itself', async () => {
    const [indicator, platform] = ends(['tlp-green'], ['tlp-green']);
    expect(sorted(await expectedPairMarkings(testContext, ['tlp-red', 'statement-1'], indicator, platform))).toEqual(['statement-1', 'tlp-green']);
    // A type both ends dropped cannot be told from it: it stays, the stricter way
    expect(sorted(await expectedPairMarkings(testContext, ['pap-red'], indicator, platform))).toEqual(['pap-red', 'tlp-green']);
  });

  it('should take a marking type an end gets', async () => {
    const [indicator, platform] = ends(['tlp-green', 'pap-red'], ['tlp-amber']);
    expect(sorted(await expectedPairMarkings(testContext, ['tlp-green'], indicator, platform))).toEqual(['pap-red', 'tlp-amber']);
  });
});

describe('marking edits of a deployment', () => {
  const [from, to] = ends(['tlp-amber'], ['pap-red']);
  const initial = { from, to, 'object-marking': ['tlp-amber', 'pap-red', 'statement-1'] };
  const edit = (operation: EditOperation, value: string[]) => [{ key: 'objectMarking', value, operation }];
  const editor = { id: 'editor', capabilities: [{ name: 'KNOWLEDGE_KNUPDATE' }] } as unknown as AuthUser;

  it('should only compute the result of edits that can relax the markings', async () => {
    expect(await markingsAfterEdits(testContext, initial['object-marking'], edit(EditOperation.Add, ['tlp-red']))).toBeUndefined();
    expect(await markingsAfterEdits(testContext, initial['object-marking'], edit(EditOperation.Remove, ['marking-definition--pap-red'])))
      .toEqual(['tlp-amber', 'statement-1']);
    expect(await markingsAfterEdits(testContext, initial['object-marking'], [
      ...edit(EditOperation.Replace, ['tlp-green']),
      ...edit(EditOperation.Add, ['pap-red']),
    ])).toEqual(['tlp-green', 'pap-red']);
  });

  it('should refuse removing or replacing away a marking of an end, whatever id form the edit uses', async () => {
    expect(await keepsPairMarkings(testContext, initial, edit(EditOperation.Remove, ['pap-red']))).toEqual(false);
    expect(await keepsPairMarkings(testContext, initial, edit(EditOperation.Remove, ['marking-definition--tlp-amber']))).toEqual(false);
    expect(await keepsPairMarkings(testContext, initial, edit(EditOperation.Replace, ['tlp-green', 'pap-red']))).toEqual(false);
    const validatorUpdate = getEntityValidatorUpdate(RELATION_DEPLOYED_ON) as ValidatorFn;
    const removal = edit(EditOperation.Remove, ['pap-red']);
    await expect(validatorUpdate(testContext, editor, { objectMarking: ['pap-red'] }, initial, removal)).rejects.toThrow('markings of its indicator');
  });

  it('should accept raising a marking, adding one, or removing a marking of the deployment itself', async () => {
    expect(await keepsPairMarkings(testContext, initial, edit(EditOperation.Remove, ['statement-1']))).toEqual(true);
    expect(await keepsPairMarkings(testContext, initial, edit(EditOperation.Replace, ['tlp-red', 'pap-red']))).toEqual(true);
    expect(await keepsPairMarkings(testContext, initial, edit(EditOperation.Add, ['tlp-green']))).toEqual(true);
    const validatorUpdate = getEntityValidatorUpdate(RELATION_DEPLOYED_ON) as ValidatorFn;
    const removal = edit(EditOperation.Remove, ['statement-1']);
    await expect(validatorUpdate(testContext, editor, { objectMarking: ['statement-1'] }, initial, removal)).resolves.toEqual(true);
  });
});
