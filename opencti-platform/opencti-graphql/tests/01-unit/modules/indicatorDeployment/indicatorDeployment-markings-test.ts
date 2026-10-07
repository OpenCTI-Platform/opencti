import { describe, expect, it, vi } from 'vitest';

import '../../../../src/modules/index';
import { expectedPairMarkings } from '../../../../src/modules/indicatorDeployment/indicatorDeployment-domain';
import { hitsSightingStixId } from '../../../../src/modules/indicatorDeployment/indicatorDeployment-utils';
import { sightingReportContext } from '../../../../src/modules/indicatorDeployment/indicatorDeployment-sightings';
import {
  isGeneratedPairSighting,
  isIndividualAuthor,
  keepsPairMarkings,
  keepsPairSharing,
  markingsAfterEdits,
} from '../../../../src/modules/iocValidation/iocValidation-validator';
import { internalFindByIds, internalLoadById } from '../../../../src/database/middleware-loader';
import { getEntityValidatorCreation, getEntityValidatorUpdate, type ValidatorFn } from '../../../../src/schema/validator-register';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../../src/schema/stixSightingRelationship';
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
// Stored elements: none unless a test gives some (a stored sighting, the author of an edit).
vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  internalFindByIds: vi.fn(async () => []),
  internalLoadById: vi.fn(async () => undefined),
}));

const ends = (indicator: string[], platform: string[]) => [{ 'object-marking': indicator }, { 'object-marking': platform }] as const;
const sorted = (ids: string[]) => [...ids].sort();

describe('markings of a pair relationship', () => {
  it('should keep a marking stricter than the ends, which may have been set on purpose', async () => {
    const [indicator, platform] = ends(['tlp-green'], ['tlp-green']);
    expect(await expectedPairMarkings(testContext, ['tlp-red'], indicator, platform)).toEqual(['tlp-red']);
  });

  it('should follow an end that raises its marking', async () => {
    const [indicator, platform] = ends(['tlp-red'], ['tlp-green']);
    expect(await expectedPairMarkings(testContext, ['tlp-green'], indicator, platform)).toEqual(['tlp-red']);
  });

  it('should keep the highest marking of a type among the ends', async () => {
    const [indicator, platform] = ends(['tlp-green'], ['tlp-red']);
    expect(await expectedPairMarkings(testContext, ['tlp-red'], indicator, platform)).toEqual(['tlp-red']);
    expect(await expectedPairMarkings(testContext, [], indicator, platform)).toEqual(['tlp-red']);
  });

  it('should keep a marking of a type neither end carries, set on the relationship itself', async () => {
    const [indicator, platform] = ends(['tlp-green'], ['tlp-green']);
    expect(sorted(await expectedPairMarkings(testContext, ['tlp-amber', 'statement-1'], indicator, platform))).toEqual(['statement-1', 'tlp-amber']);
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

  it('should refuse widening the sharing of a deployment beyond the organizations of both its ends', async () => {
    const shared = { ...initial, from: { ...from, granted: ['org-a', 'org-b'] }, to: { ...to, granted: ['org-a'] } };
    const share = (operation: EditOperation, value: string[]) => [{ key: 'objectOrganization', value, operation }];
    expect(await keepsPairSharing(testContext, shared, share(EditOperation.Add, ['org-a']))).toEqual(true);
    expect(await keepsPairSharing(testContext, shared, share(EditOperation.Add, ['org-b']))).toEqual(false);
    expect(await keepsPairSharing(testContext, shared, share(EditOperation.Replace, ['org-a', 'org-c']))).toEqual(false);
    expect(await keepsPairSharing(testContext, shared, share(EditOperation.Remove, ['org-a']))).toEqual(true);
    const validatorUpdate = getEntityValidatorUpdate(RELATION_DEPLOYED_ON) as ValidatorFn;
    const widening = share(EditOperation.Add, ['org-b']);
    await expect(validatorUpdate(testContext, editor, { objectOrganization: ['org-b'] }, shared, widening)).rejects.toThrow('organizations of both');
  });

  it('should keep the markings of the pair on the hits sighting, and leave other sightings alone', async () => {
    const indicator = { ...from, entity_type: 'Indicator', internal_id: 'indicator-1' };
    const platform = { ...to, entity_type: 'SecurityPlatform', internal_id: 'platform-1' };
    const hitsSighting = { from: indicator, to: platform, standard_id: hitsSightingStixId('indicator-1', 'platform-1'), 'object-marking': ['tlp-amber', 'pap-red'] };
    expect(await isGeneratedPairSighting(testContext, hitsSighting)).toEqual(true);
    const validatorSighting = getEntityValidatorUpdate(STIX_SIGHTING_RELATIONSHIP) as ValidatorFn;
    const removal = edit(EditOperation.Remove, ['pap-red']);
    await expect(validatorSighting(testContext, editor, { objectMarking: ['pap-red'] }, hitsSighting, removal)).rejects.toThrow('markings of its indicator');
    // What the hits sighting records is written by the hits report of the accounts reporting hits, or an administrator
    const connector = { id: 'connector', capabilities: [{ name: 'KNOWLEDGE_KNUPDATE' }, { name: 'CONNECTORAPI' }] } as unknown as AuthUser;
    const administrator = { id: 'admin', capabilities: [{ name: 'BYPASS' }] } as unknown as AuthUser;
    const recount = [{ key: 'attribute_count', value: [1] }];
    await expect(validatorSighting(testContext, editor, { attribute_count: [1] }, hitsSighting, recount)).rejects.toThrow('deployment state');
    await expect(validatorSighting(testContext, editor, { description: 'x' }, hitsSighting, [{ key: 'description', value: ['x'] }])).rejects.toThrow('deployment state');
    await expect(validatorSighting(testContext, connector, { attribute_count: [1] }, hitsSighting, recount)).rejects.toThrow('indicatorReportHits');
    await expect(validatorSighting(sightingReportContext(testContext), connector, { attribute_count: [1] }, hitsSighting, recount)).resolves.toEqual(true);
    await expect(validatorSighting(testContext, administrator, { attribute_count: [1] }, hitsSighting, recount)).resolves.toEqual(true);
    await expect(validatorSighting(testContext, editor, { objectLabel: ['triage'] }, hitsSighting, [{ key: 'objectLabel', value: ['triage'] }])).resolves.toEqual(true);
    // Nor can its deterministic id be taken by a sighting someone else creates
    const validatorSightingCreation = getEntityValidatorCreation(STIX_SIGHTING_RELATIONSHIP) as ValidatorFn;
    const squat = { from: indicator, to: platform, stix_id: hitsSighting.standard_id, objectMarking: ['tlp-amber', 'pap-red'] };
    await expect(validatorSightingCreation(testContext, editor, squat)).rejects.toThrow('deployment state');
    await expect(validatorSightingCreation(testContext, connector, squat)).rejects.toThrow('indicatorReportHits');
    await expect(validatorSightingCreation(testContext, administrator, squat)).resolves.toEqual(true);
    // A sighting of another kind of entity is never one of the pair sightings
    const malwareSighting = { ...hitsSighting, from: { ...indicator, entity_type: 'Malware' } };
    expect(await isGeneratedPairSighting(testContext, malwareSighting)).toEqual(false);
    await expect(validatorSighting(testContext, editor, { objectMarking: ['pap-red'] }, malwareSighting, removal)).resolves.toEqual(true);
  });

  it('should create a generated sighting with the markings of its pair only, for administrators too', async () => {
    const indicator = { ...from, entity_type: 'Indicator', internal_id: 'indicator-1' };
    const platform = { ...to, entity_type: 'SecurityPlatform', internal_id: 'platform-1' };
    const administrator = { id: 'admin', capabilities: [{ name: 'BYPASS' }] } as unknown as AuthUser;
    const validatorSightingCreation = getEntityValidatorCreation(STIX_SIGHTING_RELATIONSHIP) as ValidatorFn;
    const unmarked = { from: indicator, to: platform, stix_id: hitsSightingStixId('indicator-1', 'platform-1'), objectMarking: ['tlp-amber'] };
    await expect(validatorSightingCreation(testContext, administrator, unmarked)).rejects.toThrow('markings of its indicator');
    // The upsert of the stored sighting keeps its markings: the input does not need to repeat them
    vi.mocked(internalFindByIds).mockResolvedValueOnce([{ 'object-marking': ['tlp-amber', 'pap-red'] }] as never);
    await expect(validatorSightingCreation(testContext, administrator, unmarked)).resolves.toEqual(true);
  });

  it('should refuse an individual as author of a deployment or of a generated sighting, for administrators too', async () => {
    const indicator = { ...from, entity_type: 'Indicator', internal_id: 'indicator-1' };
    const platform = { ...to, entity_type: 'SecurityPlatform', internal_id: 'platform-1' };
    const administrator = { id: 'admin', capabilities: [{ name: 'BYPASS' }] } as unknown as AuthUser;
    const individual = { entity_type: 'Individual', internal_id: 'individual-1' };
    const organization = { entity_type: 'Organization', internal_id: 'organization-1' };
    const markings = ['tlp-amber', 'pap-red'];
    expect(await isIndividualAuthor(testContext, [individual])).toEqual(true);
    expect(await isIndividualAuthor(testContext, organization)).toEqual(false);
    expect(await isIndividualAuthor(testContext, undefined)).toEqual(false);
    // Creation and upsert of a deployment, author resolved or given by id
    const deploymentCreation = getEntityValidatorCreation(RELATION_DEPLOYED_ON) as ValidatorFn;
    await expect(deploymentCreation(testContext, administrator, { from: indicator, to: platform, objectMarking: markings, createdBy: individual }))
      .rejects.toThrow('not authored by an individual');
    await expect(deploymentCreation(testContext, administrator, { from: indicator, to: platform, objectMarking: markings, createdBy: organization }))
      .resolves.toEqual(true);
    vi.mocked(internalLoadById).mockResolvedValueOnce(individual as never);
    await expect(deploymentCreation(testContext, administrator, { from: indicator, to: platform, objectMarking: markings, createdBy: 'individual-1' }))
      .rejects.toThrow('not authored by an individual');
    // Field edit or reference added
    const deploymentUpdate = getEntityValidatorUpdate(RELATION_DEPLOYED_ON) as ValidatorFn;
    const authorEdit = [{ key: 'createdBy', value: ['individual-1'], operation: EditOperation.Add }];
    vi.mocked(internalLoadById).mockResolvedValueOnce(individual as never);
    await expect(deploymentUpdate(testContext, administrator, { createdBy: ['individual-1'] }, initial, authorEdit)).rejects.toThrow('not authored by an individual');
    const authorRemoval = [{ key: 'createdBy', value: ['individual-1'], operation: EditOperation.Remove }];
    await expect(deploymentUpdate(testContext, administrator, { createdBy: ['individual-1'] }, initial, authorRemoval)).resolves.toEqual(true);
    // The hits sighting of the pair, created or edited
    const hitsId = hitsSightingStixId('indicator-1', 'platform-1');
    const sightingCreation = getEntityValidatorCreation(STIX_SIGHTING_RELATIONSHIP) as ValidatorFn;
    await expect(sightingCreation(testContext, administrator, { from: indicator, to: platform, stix_id: hitsId, objectMarking: markings, createdBy: individual }))
      .rejects.toThrow('not authored by an individual');
    const sightingUpdate = getEntityValidatorUpdate(STIX_SIGHTING_RELATIONSHIP) as ValidatorFn;
    const hitsSighting = { from: indicator, to: platform, standard_id: hitsId, 'object-marking': markings };
    vi.mocked(internalLoadById).mockResolvedValueOnce(individual as never);
    await expect(sightingUpdate(testContext, administrator, { createdBy: ['individual-1'] }, hitsSighting, authorEdit)).rejects.toThrow('not authored by an individual');
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
