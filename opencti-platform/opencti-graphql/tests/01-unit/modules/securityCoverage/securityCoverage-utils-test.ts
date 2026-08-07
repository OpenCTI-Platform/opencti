import { describe, expect, it } from 'vitest';
import { shouldHandleHasCoveredRel } from '../../../../src/modules/securityCoverage/securityCoverage-utils';

describe('Function shouldHandleHasCoveredRel()', () => {
  it('should return false if not has-covered relationship', () => {
    expect(shouldHandleHasCoveredRel({
      relationship_type: 'uses',
      external_uri: 'http://192.168.1.150:8080/admin/scenarios/001d6ae0-4344-4467-99d5-eb4b6962fd4b',
      fromId: 'security-coverage--c76bfcfe-2be5-500f-9b81-367457f1088f',
      toId: 'intrusion-set--d12c5319-f308-5fef-9336-20484af42084',
    })).toEqual(false);
  });

  it('should return false if not securityCoverage', () => {
    expect(shouldHandleHasCoveredRel({
      relationship_type: 'has-covered',
      external_uri: 'http://192.168.1.150:8080/admin/scenarios/001d6ae0-4344-4467-99d5-eb4b6962fd4b',
      fromId: 'security-coverage-result--c76bfcfe-2be5-500f-9b81-367457f1088f',
      toId: 'intrusion-set--d12c5319-f308-5fef-9336-20484af42084',
    })).toEqual(false);
  });

  it('should return true if all conditions respected', () => {
    expect(shouldHandleHasCoveredRel({
      relationship_type: 'has-covered',
      external_uri: 'http://192.168.1.150:8080/admin/scenarios/001d6ae0-4344-4467-99d5-eb4b6962fd4b',
      fromId: 'security-coverage--c76bfcfe-2be5-500f-9b81-367457f1088f',
      toId: 'intrusion-set--d12c5319-f308-5fef-9336-20484af42084',
    })).toEqual(true);
  });
});
