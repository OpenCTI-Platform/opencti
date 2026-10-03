import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import { carriesValidationProof, touchesValidationFields } from '../../../../src/modules/iocValidation/iocValidation-validator';
import { getEntityValidatorCreation, getEntityValidatorUpdate } from '../../../../src/schema/validator-register';
import { RELATION_DEPLOYED_ON } from '../../../../src/modules/indicatorDeployment/indicatorDeployment-types';

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
  });
});
