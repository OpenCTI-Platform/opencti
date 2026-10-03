import { describe, expect, it } from 'vitest';
import * as testers from '../../../../src/utils/filtering/filtering-stix/stix-testers';
import { FILTER_KEY_TESTERS_MAP } from '../../../../src/utils/filtering/filtering-stix/stix-testers';
import type { Filter } from '../../../../src/generated/graphql';
import type { ReadonlyStix } from '../../../../src/utils/filtering/boolean-logic-engine';

const EXT = 'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba';

const deployedOn = (deployment_status: string, validation_status: string) => ({
  id: 'relationship--9b1d3f5a-3333-4c4d-9e5f-fedcbafedcba',
  type: 'relationship',
  relationship_type: 'deployed-on',
  extensions: { [EXT]: { deployment_status, validation_status } },
}) as unknown as ReadonlyStix;

const uses = { id: 'relationship--1b1d3f5a-3333-4c4d-9e5f-fedcbafedcba', type: 'relationship', relationship_type: 'uses', extensions: { [EXT]: {} } } as unknown as ReadonlyStix;

const filter = (key: string, values: string[], operator = 'eq') => ({ key: [key], mode: 'or', operator, values }) as Filter;

describe('Dissemination assurance stix filter testers (triggers)', () => {
  it('should be registered for live triggers, streams and playbooks', () => {
    expect(FILTER_KEY_TESTERS_MAP.deployment_status).toBeDefined();
    expect(FILTER_KEY_TESTERS_MAP.validation_status).toBeDefined();
  });

  it('should match deployment failed and expired deployments', () => {
    expect(testers.testDeploymentStatus(deployedOn('failed', 'not_requested'), filter('deployment_status', ['failed']))).toEqual(true);
    expect(testers.testDeploymentStatus(deployedOn('active', 'not_requested'), filter('deployment_status', ['failed']))).toEqual(false);
    expect(testers.testDeploymentStatus(deployedOn('expired', 'detected'), filter('deployment_status', ['failed', 'expired']))).toEqual(true);
    expect(testers.testDeploymentStatus(deployedOn('expired', 'detected'), filter('deployment_status', ['expired'], 'not_eq'))).toEqual(false);
    expect(testers.testDeploymentStatus(uses, filter('deployment_status', ['failed']))).toEqual(false);
  });

  it('should match missed validations', () => {
    expect(testers.testValidationStatus(deployedOn('active', 'missed'), filter('validation_status', ['missed']))).toEqual(true);
    expect(testers.testValidationStatus(deployedOn('active', 'detected'), filter('validation_status', ['missed']))).toEqual(false);
    expect(testers.testValidationStatus(uses, filter('validation_status', [], 'nil'))).toEqual(true);
  });
});
