import { describe, expect, it } from 'vitest';
import convertSecurityCoverageResultToStix from '../../../../src/modules/securityCoverage/securityCoverageResult/securityCoverageResult-converter';
import {
  ATTRIBUTE_RESULT_OF,
  ENTITY_TYPE_SECURITY_COVERAGE_RESULT,
  INPUT_RESULT_OF,
  type StoreEntitySecurityCoverageResult,
} from '../../../../src/modules/securityCoverage/securityCoverageResult/securityCoverageResult-types';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';

const BASE_INSTANCE = {
  _index: 'opencti_internal_objects-000001',
  internal_id: 'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa',
  standard_id: 'security-coverage-result--aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa',
  x_opencti_stix_ids: [],
  created_at: '2025-01-01T00:00:00.000Z',
  updated_at: '2025-01-02T00:00:00.000Z',
  base_type: 'ENTITY' as const,
  entity_type: ENTITY_TYPE_SECURITY_COVERAGE_RESULT,
  parent_types: ['Basic-Object', 'Internal-Object'],
};

describe('SecurityCoverageResult converter', () => {
  it('should return expected STIX result', () => {
    const instance = {
      ...BASE_INSTANCE,
      name: 'security coverage result',
      external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a131',
      coverage_last_result: '2025-02-01T00:00:00.000Z',
      coverage_valid_from: '2025-03-01T00:00:00.000Z',
      coverage_valid_to: '2025-04-01T00:00:00.000Z',
      coverage_information: [{ coverage_name: 'vulnerability', coverage_score: 40 }],
      [INPUT_RESULT_OF]: { standard_id: 'security-coverage-aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa' },
    } as unknown as StoreEntitySecurityCoverageResult;

    const expectedExtensions = {
      [STIX_EXT_OCTI]: {
        extension_type: 'new-sdo',
        id: 'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa',
        type: 'Security-Coverage-Result',
        created_at: '2025-01-01T00:00:00.000Z',
        updated_at: '2025-01-02T00:00:00.000Z',
        is_inferred: false,
      },
    };

    const result = convertSecurityCoverageResultToStix(instance);
    expect(result.name).toEqual('security coverage result');
    expect(result.external_uri).toEqual('http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a131');
    expect(result.coverage_last_result).toEqual('2025-02-01T00:00:00.000Z');
    expect(result.coverage_valid_from).toEqual('2025-03-01T00:00:00.000Z');
    expect(result.coverage_valid_to).toEqual('2025-04-01T00:00:00.000Z');
    expect(result.coverage).toEqual([{ name: 'vulnerability', score: 40 }]);
    expect(result[ATTRIBUTE_RESULT_OF]).toEqual('security-coverage-aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa');
    expect(result.extensions).toEqual(expectedExtensions);
    expect(result.covered).toEqual(true);
  });

  it('should return expected STIX result when there is no coverage_information', () => {
    const instance = {
      ...BASE_INSTANCE,
      name: 'security coverage result',
      external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a131',
      coverage_last_result: '2025-02-01T00:00:00.000Z',
      coverage_valid_from: '2025-03-01T00:00:00.000Z',
      coverage_valid_to: '2025-04-01T00:00:00.000Z',
      [INPUT_RESULT_OF]: { standard_id: 'security-coverage-aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa' },
    } as unknown as StoreEntitySecurityCoverageResult;

    const result = convertSecurityCoverageResultToStix(instance);

    expect(result.coverage).toEqual([]);
    expect(result.covered).toEqual(false);
  });
});
