import { describe, expect, it, vi } from 'vitest';

import '../../../../src/modules/index';
import {
  carriesLifecycleState,
  carriesValidationProof,
  coversPairMarkings,
  coversUpsertPairMarkings,
  setsValidityWindow,
  invalidStatusField,
  isLifecycleWriter,
  touchesLifecycleFields,
  touchesValidationFields,
} from '../../../../src/modules/iocValidation/iocValidation-validator';
import { isTrustedDeploymentReporter } from '../../../../src/modules/iocValidation/iocValidation-utils';
import { missingConnectorCapabilities, summarizeRequestPairs, withPairOutcomes } from '../../../../src/modules/iocValidation/iocValidation-domain';
import { getEntityValidatorCreation, getEntityValidatorUpdate, type ValidatorFn } from '../../../../src/schema/validator-register';
import { RELATION_DEPLOYED_ON } from '../../../../src/modules/indicatorDeployment/indicatorDeployment-types';
import type { AuthUser } from '../../../../src/types/user';
import { EXPIRATION_MANAGER_USER } from '../../../../src/utils/access';
import { ENTITY_TYPE_IDENTITY_INDIVIDUAL } from '../../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../../src/modules/organization/organization-types';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../../src/schema/stixSightingRelationship';
import { ENTITY_TYPE_INDICATOR } from '../../../../src/modules/indicator/indicator-types';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../../../../src/modules/securityPlatform/securityPlatform-types';
import { hitsSightingStixId } from '../../../../src/modules/indicatorDeployment/indicatorDeployment-utils';
import { sightingReportContext } from '../../../../src/modules/indicatorDeployment/indicatorDeployment-sightings';
import { EditOperation } from '../../../../src/generated/graphql';
import { testContext } from '../../../utils/testQuery';

// Marking definitions come from the platform cache: here every marking is of its own type, so cleaning keeps them all.
vi.mock('../../../../src/utils/markingDefinition-utils', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/utils/markingDefinition-utils')>()),
  cleanMarkings: async (_context: unknown, values: string[]) => [...new Set(values)].map((id) => ({ internal_id: id })),
}));
vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/cache')>()),
  getEntitiesMapFromCache: async () => new Map(['tlp-amber', 'pap-red'].map((id) => [id, { internal_id: id }])),
}));

describe('Deployment validation fields guard', () => {
  it('should be registered for creation and update of deployed-on relationships', () => {
    expect(getEntityValidatorCreation(RELATION_DEPLOYED_ON)).toBeDefined();
    expect(getEntityValidatorUpdate(RELATION_DEPLOYED_ON)).toBeDefined();
  });

  it('should only see proof in a verdict, a validation date or a run reference', () => {
    expect(carriesValidationProof({ deployment_status: 'deployed' })).toEqual(false);
    expect(carriesValidationProof({ validation_status: 'not_requested' })).toEqual(false);
    expect(carriesValidationProof({ validation_status: ['not_requested'], validation_run_id: null })).toEqual(false);
    expect(carriesValidationProof({ validation_status: 'detected' })).toEqual(true);
    expect(carriesValidationProof({ validation_status: ['missed'] })).toEqual(true);
    expect(carriesValidationProof({ last_validation_at: '2026-10-03T12:00:00.000Z' })).toEqual(true);
    expect(carriesValidationProof({ validation_run_id: 'request-1' })).toEqual(true);
  });

  it('should guard every change of a validation field on update, erasing included', () => {
    expect(touchesValidationFields({ deployment_status: ['active'] })).toEqual(false);
    expect(touchesValidationFields({ validation_status: ['not_requested'] })).toEqual(true);
    expect(touchesValidationFields({ validation_run_id: [null] })).toEqual(true);
    expect(touchesValidationFields({ validation_status: undefined })).toEqual(false);
  });
});

describe('Deployment lifecycle fields guard', () => {
  const user = (capabilities: string[]) => ({ id: 'user-1', capabilities: capabilities.map((name) => ({ name })) }) as unknown as AuthUser;
  const editor = user(['KNOWLEDGE_KNUPDATE']);
  const connector = user(['KNOWLEDGE_KNUPDATE', 'CONNECTORAPI']);
  const administrator = user(['BYPASS']);

  it('should only see deployment state in values other than the defaults of a new deployment', () => {
    expect(carriesLifecycleState({ description: 'manual' })).toEqual(false);
    expect(carriesLifecycleState({ deployment_status: 'pending', hit_count: 0, error_message: '' })).toEqual(false);
    expect(carriesLifecycleState({ deployment_status: ['active'] })).toEqual(true);
    expect(carriesLifecycleState({ hit_count: 3 })).toEqual(true);
    expect(carriesLifecycleState({ first_hit_at: '2026-10-03T12:00:00.000Z' })).toEqual(true);
    expect(carriesLifecycleState({ external_id: 'vendor-1' })).toEqual(true);
  });

  it('should guard every change of a lifecycle field, resets included', () => {
    expect(touchesLifecycleFields({ revoked: [true] })).toEqual(false);
    expect(touchesLifecycleFields({ deployment_status: ['pending'] })).toEqual(true);
    expect(touchesLifecycleFields({ hit_count: [0] })).toEqual(true);
    expect(touchesLifecycleFields({ last_hit_at: [null] })).toEqual(true);
  });

  it('should leave the lifecycle to connector accounts and administrators', () => {
    expect(isLifecycleWriter(editor)).toEqual(false);
    expect(isLifecycleWriter(connector)).toEqual(true);
    expect(isLifecycleWriter(administrator)).toEqual(true);
  });

  it('should name, in plain words, the capabilities an IOC validation connector account misses', () => {
    expect(missingConnectorCapabilities(connector)).toEqual([]);
    expect(missingConnectorCapabilities(administrator)).toEqual([]);
    expect(missingConnectorCapabilities(editor)).toEqual(['"Connectors API usage"']);
    expect(missingConnectorCapabilities(user([]))).toEqual(['"Update knowledge"', '"Connectors API usage"']);
  });

  it('should refuse a regular editor writing deployment state on creation or edition', async () => {
    const validatorCreation = getEntityValidatorCreation(RELATION_DEPLOYED_ON) as ValidatorFn;
    const validatorUpdate = getEntityValidatorUpdate(RELATION_DEPLOYED_ON) as ValidatorFn;
    await expect(validatorCreation(testContext, editor, { deployment_status: 'active', hit_count: 9 })).rejects.toThrow('deployment state');
    await expect(validatorUpdate(testContext, editor, { deployment_status: ['pending'] }, {})).rejects.toThrow('deployment state');
    await expect(validatorUpdate(testContext, administrator, { deployment_status: ['pending'] }, {})).resolves.toEqual(true);
    await expect(validatorUpdate(testContext, connector, { hit_count: [4] }, {})).resolves.toEqual(true);
    await expect(validatorUpdate(testContext, editor, { description: ['notes'] }, {})).resolves.toEqual(true);
  });

  it('should reserve the expired status to the deployment manager and administrators, whatever the write path', async () => {
    const validatorCreation = getEntityValidatorCreation(RELATION_DEPLOYED_ON) as ValidatorFn;
    const validatorUpdate = getEntityValidatorUpdate(RELATION_DEPLOYED_ON) as ValidatorFn;
    await expect(validatorCreation(testContext, connector, { deployment_status: 'expired' })).rejects.toThrow('reserved to the platform');
    await expect(validatorUpdate(testContext, connector, { deployment_status: ['expired'] }, {})).rejects.toThrow('reserved to the platform');
    await expect(validatorCreation(testContext, administrator, { deployment_status: 'expired' })).resolves.toEqual(true);
    await expect(validatorUpdate(testContext, administrator, { deployment_status: ['expired'] }, {})).resolves.toEqual(true);
    await expect(validatorUpdate(testContext, EXPIRATION_MANAGER_USER, { deployment_status: ['expired'] }, {})).resolves.toEqual(true);
    await expect(validatorUpdate(testContext, connector, { deployment_status: ['removed'] }, {})).resolves.toEqual(true);
  });

  it('should let a regular editor create a new deployment in its default state', async () => {
    const validatorCreation = getEntityValidatorCreation(RELATION_DEPLOYED_ON) as ValidatorFn;
    await expect(validatorCreation(testContext, editor, { description: 'manual' })).resolves.toEqual(true);
    // Defaults on a pair without deployment (no existing relationship to reset)
    await expect(validatorCreation(testContext, editor, { deployment_status: 'pending', hit_count: 0 })).resolves.toEqual(true);
    await expect(validatorCreation(testContext, connector, { deployment_status: 'active', hit_count: 9 })).resolves.toEqual(true);
  });

  it('should only let a connector account among the creators write a verdict', async () => {
    const validatorUpdate = getEntityValidatorUpdate(RELATION_DEPLOYED_ON) as ValidatorFn;
    // An editor joins the creators by upserting the relationship, which does not make it a reporter of the platform
    const upserted = { creator_id: ['connector-user', 'user-1'] };
    await expect(validatorUpdate(testContext, editor, { validation_status: ['detected'] }, upserted)).rejects.toThrow('Validation results');
    await expect(validatorUpdate(testContext, editor, { validation_status: ['not_requested'] }, upserted)).rejects.toThrow('Validation results');
    await expect(validatorUpdate(testContext, connector, { validation_status: ['detected'] }, upserted)).resolves.toEqual(true);
    expect(isTrustedDeploymentReporter(upserted, editor)).toEqual(false);
    expect(isTrustedDeploymentReporter(upserted, connector)).toEqual(true);
    expect(isTrustedDeploymentReporter({ creator_id: 'connector-user' }, connector)).toEqual(false);
    expect(isTrustedDeploymentReporter({ creator_id: null }, administrator)).toEqual(false);
  });
});

describe('Deployment markings guard', () => {
  const from = { 'object-marking': ['tlp-amber'] };
  const to = { 'object-marking': ['pap-red'] };

  it('should require the markings of the indicator and of the security platform on creation', async () => {
    expect(await coversPairMarkings(testContext, { from, to, objectMarking: ['tlp-amber', 'pap-red'] })).toEqual(true);
    expect(await coversPairMarkings(testContext, { from, to, objectMarking: [{ internal_id: 'tlp-amber' }, { internal_id: 'pap-red' }] })).toEqual(true);
    expect(await coversPairMarkings(testContext, { from, to, objectMarking: ['tlp-amber'] })).toEqual(false);
    expect(await coversPairMarkings(testContext, { from, to })).toEqual(false);
    expect(await coversPairMarkings(testContext, { deployment_status: 'pending' })).toEqual(true);
  });

  it('should check an upsert on the markings it ends with: the stored ones, those of the input, then its operations', async () => {
    const stored = { 'object-marking': ['tlp-amber', 'pap-red'] };
    // A description-only upsert of a marked deployment keeps its markings
    expect(await coversUpsertPairMarkings(testContext, { from, to, description: 'notes' }, stored)).toEqual(true);
    expect(await coversUpsertPairMarkings(testContext, { from, to, objectMarking: ['pap-red'] }, { 'object-marking': ['tlp-amber'] })).toEqual(true);
    expect(await coversUpsertPairMarkings(testContext, { from, to }, { 'object-marking': ['tlp-amber'] })).toEqual(false);
    const operation = (kind: string, value: string[]) => ({ from, to, upsertOperations: [{ key: 'objectMarking', operation: kind, value }] });
    expect(await coversUpsertPairMarkings(testContext, operation('remove', ['pap-red']), stored)).toEqual(false);
    expect(await coversUpsertPairMarkings(testContext, operation('add', ['pap-red']), { 'object-marking': ['tlp-amber'] })).toEqual(true);
    expect(await coversUpsertPairMarkings(testContext, { deployment_status: 'active' }, stored)).toEqual(true);
  });

  it('should refuse a deployment less restricted than its security platform, whoever creates it', async () => {
    const validatorCreation = getEntityValidatorCreation(RELATION_DEPLOYED_ON) as ValidatorFn;
    const administrator = { id: 'admin', capabilities: [{ name: 'BYPASS' }] } as unknown as AuthUser;
    await expect(validatorCreation(testContext, administrator, { from, to, objectMarking: ['tlp-amber'] })).rejects.toThrow('markings of its indicator');
    await expect(validatorCreation(testContext, administrator, { from, to, objectMarking: ['tlp-amber', 'pap-red'] })).resolves.toEqual(true);
  });

  it('should refuse an individual author given by the field or by an upsert operation, for administrators too', async () => {
    const validatorCreation = getEntityValidatorCreation(RELATION_DEPLOYED_ON) as ValidatorFn;
    const administrator = { id: 'admin', capabilities: [{ name: 'BYPASS' }] } as unknown as AuthUser;
    const individual = { entity_type: ENTITY_TYPE_IDENTITY_INDIVIDUAL, internal_id: 'individual' };
    const organization = { entity_type: ENTITY_TYPE_IDENTITY_ORGANIZATION, internal_id: 'organization' };
    const marked = { from, to, objectMarking: ['tlp-amber', 'pap-red'] };
    const authorOperation = (author: unknown) => ({ ...marked, upsertOperations: [{ key: 'createdBy', operation: 'replace', value: [author] }] });
    await expect(validatorCreation(testContext, administrator, { ...marked, createdBy: individual })).rejects.toThrow('not authored by an individual');
    await expect(validatorCreation(testContext, administrator, authorOperation(individual))).rejects.toThrow('not authored by an individual');
    await expect(validatorCreation(testContext, administrator, authorOperation(organization))).resolves.toEqual(true);
  });
});

describe('Deployment identity guard', () => {
  it('should refuse a validity window, which would give the pair a second deployment', async () => {
    expect(setsValidityWindow({ deployment_status: 'active' })).toEqual(false);
    expect(setsValidityWindow({ start_time: '1970-01-01T00:00:00.000Z', stop_time: '5138-11-16T09:46:40.000Z' })).toEqual(false);
    expect(setsValidityWindow({ start_time: '2026-10-01T00:00:00.000Z' })).toEqual(true);
    expect(setsValidityWindow({ stop_time: ['2026-12-31T00:00:00.000Z'] })).toEqual(true);
    const validatorCreation = getEntityValidatorCreation(RELATION_DEPLOYED_ON) as ValidatorFn;
    const validatorUpdate = getEntityValidatorUpdate(RELATION_DEPLOYED_ON) as ValidatorFn;
    const administrator = { id: 'admin', capabilities: [{ name: 'BYPASS' }] } as unknown as AuthUser;
    await expect(validatorCreation(testContext, administrator, { start_time: '2026-10-01T00:00:00.000Z' })).rejects.toThrow('no start or stop time');
    await expect(validatorUpdate(testContext, administrator, { stop_time: ['2026-12-31T00:00:00.000Z'] }, {})).rejects.toThrow('no start or stop time');
  });

  it('should refuse a status outside the statuses of its field, for administrators too', async () => {
    expect(invalidStatusField({ deployment_status: 'active', validation_status: ['detected'] })).toBeUndefined();
    expect(invalidStatusField({ hit_count: 2 })).toBeUndefined();
    expect(invalidStatusField({ deployment_status: 'invalid-status' })).toEqual('deployment_status');
    expect(invalidStatusField({ validation_status: ['invalid-status'] })).toEqual('validation_status');
    const validatorCreation = getEntityValidatorCreation(RELATION_DEPLOYED_ON) as ValidatorFn;
    const validatorUpdate = getEntityValidatorUpdate(RELATION_DEPLOYED_ON) as ValidatorFn;
    const administrator = { id: 'admin', capabilities: [{ name: 'BYPASS' }] } as unknown as AuthUser;
    await expect(validatorCreation(testContext, administrator, { deployment_status: 'invalid-status' })).rejects.toThrow('Status is not one of the statuses');
    await expect(validatorUpdate(testContext, administrator, { validation_status: ['invalid-status'] }, {})).rejects.toThrow('Status is not one of the statuses');
  });
});

describe('Hits sighting guard', () => {
  const user = (capabilities: string[]) => ({ id: 'user-1', capabilities: capabilities.map((name) => ({ name })) }) as unknown as AuthUser;
  const connector = user(['KNOWLEDGE_KNUPDATE', 'CONNECTORAPI']);
  const administrator = user(['BYPASS']);
  const indicatorId = 'a6d6f6a4-6a87-4c39-9d4f-7d2f3e6c1a01';
  const platformId = 'b3c1e0d2-5f44-4b1e-8a3c-2e9d7f6a4b02';
  const hitsId = hitsSightingStixId(indicatorId, platformId);
  const hitsSighting = {
    from: { entity_type: ENTITY_TYPE_INDICATOR, internal_id: indicatorId },
    to: { entity_type: ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM, internal_id: platformId },
    standard_id: 'sighting--0f1e2d3c-4b5a-4968-8778-695a4b3c2d1e',
    x_opencti_stix_ids: [hitsId],
  };
  const validatorUpdate = () => getEntityValidatorUpdate(STIX_SIGHTING_RELATIONSHIP) as ValidatorFn;
  const countEdit = [{ key: 'attribute_count', value: ['9'] }];

  it('should leave what it records to its report, even for the reporting connector account', async () => {
    await expect(validatorUpdate()(testContext, connector, {}, hitsSighting, countEdit)).rejects.toThrow('indicatorReportHits');
    await expect(validatorUpdate()(sightingReportContext(testContext), connector, {}, hitsSighting, countEdit)).resolves.toEqual(true);
    await expect(validatorUpdate()(testContext, administrator, {}, hitsSighting, countEdit)).resolves.toEqual(true);
  });

  it('should keep its identifier, for administrators too', async () => {
    const removal = [{ key: 'x_opencti_stix_ids', value: [], operation: EditOperation.Replace }];
    await expect(validatorUpdate()(testContext, administrator, {}, hitsSighting, removal)).rejects.toThrow('keeps the identifier');
    const kept = [{ key: 'x_opencti_stix_ids', value: [hitsSighting.standard_id], operation: EditOperation.Remove }];
    await expect(validatorUpdate()(testContext, administrator, {}, hitsSighting, kept)).resolves.toEqual(true);
  });
});

describe('Request pair outcomes', () => {
  it('should keep the outcome of a pair that a newer request took over', () => {
    const pairs = [
      { indicator_id: 'i1', platform_id: 'p1', deployed_on_id: 'd1', validation_status: 'detected' },
      { indicator_id: 'i2', platform_id: 'p1', deployed_on_id: 'd2' },
    ];
    // d1 now belongs to a newer request (not bound any more), d2 is still bound and missed
    const withOutcomes = withPairOutcomes(pairs, [{ internal_id: 'd2', validation_status: 'missed' }]);
    expect(withOutcomes.map((pair) => pair.validation_status)).toEqual(['detected', 'missed']);
    expect(summarizeRequestPairs(withOutcomes, 1)).toEqual(expect.objectContaining({ total: 2, detected: 1, missed: 1, requested: 0, skipped: 1 }));
  });

  it('should keep a timed out pair marked only while its outcome is the timeout error', () => {
    const pairs = [
      { indicator_id: 'i1', platform_id: 'p1', deployed_on_id: 'd1', validation_status: 'error', timed_out: true },
      { indicator_id: 'i2', platform_id: 'p1', deployed_on_id: 'd2', validation_status: 'error', timed_out: true },
    ];
    // d1 got a late verdict for this request, d2 still carries the timeout error
    const withOutcomes = withPairOutcomes(pairs, [{ internal_id: 'd1', validation_status: 'detected' }, { internal_id: 'd2', validation_status: 'error' }]);
    expect(withOutcomes).toEqual([
      { indicator_id: 'i1', platform_id: 'p1', deployed_on_id: 'd1', validation_status: 'detected' },
      { indicator_id: 'i2', platform_id: 'p1', deployed_on_id: 'd2', validation_status: 'error', timed_out: true },
    ]);
  });
});
