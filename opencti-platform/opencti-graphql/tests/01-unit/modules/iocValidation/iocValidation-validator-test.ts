import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import {
  carriesLifecycleState,
  carriesValidationProof,
  isLifecycleWriter,
  touchesLifecycleFields,
  touchesValidationFields,
} from '../../../../src/modules/iocValidation/iocValidation-validator';
import { isTrustedDeploymentReporter } from '../../../../src/modules/iocValidation/iocValidation-utils';
import { getEntityValidatorCreation, getEntityValidatorUpdate, type ValidatorFn } from '../../../../src/schema/validator-register';
import { RELATION_DEPLOYED_ON } from '../../../../src/modules/indicatorDeployment/indicatorDeployment-types';
import type { AuthUser } from '../../../../src/types/user';
import { testContext } from '../../../utils/testQuery';

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

  it('should refuse a regular editor writing deployment state on creation or edition', async () => {
    const validatorCreation = getEntityValidatorCreation(RELATION_DEPLOYED_ON) as ValidatorFn;
    const validatorUpdate = getEntityValidatorUpdate(RELATION_DEPLOYED_ON) as ValidatorFn;
    await expect(validatorCreation(testContext, editor, { deployment_status: 'active', hit_count: 9 })).rejects.toThrow('deployment state');
    await expect(validatorUpdate(testContext, editor, { deployment_status: ['pending'] }, {})).rejects.toThrow('deployment state');
    await expect(validatorUpdate(testContext, administrator, { deployment_status: ['pending'] }, {})).resolves.toEqual(true);
    await expect(validatorUpdate(testContext, connector, { hit_count: [4] }, {})).resolves.toEqual(true);
    await expect(validatorUpdate(testContext, editor, { description: ['notes'] }, {})).resolves.toEqual(true);
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
