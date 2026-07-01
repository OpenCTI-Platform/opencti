import { describe, expect, it } from 'vitest';
import { ENTITY_TYPE_SECURITY_COVERAGE_RESULT } from '../../../../src/modules/securityCoverage/securityCoverageResult/securityCoverageResult-types';
import { generateStandardId } from '../../../../src/schema/identifier';

import '../../../../src/modules/securityCoverage/securityCoverageResult/securityCoverageResult';

describe('SecurityCoverageResult identifier', () => {
  const NAME_1 = 'Result #1';
  const NAME_2 = 'Result #2';
  const SC_1 = 'security-coverage-1232121a12e';
  const SC_2 = 'security-coverage-1232121472165';
  const URI_1 = 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a131';
  const URI_2 = 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd39375';

  const generateId = (
    sc: string | null,
    name: string | null,
    uri: string | null,
  ) => generateStandardId(
    ENTITY_TYPE_SECURITY_COVERAGE_RESULT,
    {
      resultOf: { standard_id: sc },
      name,
      external_uri: uri,
    },
  );

  it('should generate all different identifiers', () => {
    const identifiers = [
      generateId(SC_1, null, null),
      generateId(SC_2, null, null),
      generateId(null, NAME_1, null),
      generateId(null, NAME_2, null),
      generateId(null, null, URI_1),
      generateId(null, null, URI_2),
      generateId(SC_1, NAME_1, null),
      generateId(SC_1, NAME_2, null),
      generateId(SC_1, null, URI_1),
      generateId(SC_1, null, URI_2),
      generateId(SC_2, NAME_1, null),
      generateId(null, NAME_1, URI_1),
      generateId(null, NAME_1, URI_2),
      generateId(SC_2, null, URI_1),
      generateId(null, NAME_2, URI_1),
      generateId(SC_1, NAME_1, URI_1),
      generateId(SC_1, NAME_2, URI_1),
      generateId(SC_1, NAME_1, URI_2),
      generateId(SC_2, NAME_1, URI_1),
      generateId(SC_2, NAME_2, URI_1),
      generateId(SC_2, NAME_1, URI_2),
      generateId(SC_1, NAME_2, URI_2),
      generateId(SC_2, NAME_2, URI_2),
    ];
    expect(identifiers.length).toEqual(new Set(identifiers).size);
  });

  describe('using same ref resultOf', () => {
    it('should have same ID if given same name (no external_uri)', () => {
      const standardId1 = generateId(SC_1, NAME_1, null);
      const standardId2 = generateId(SC_1, NAME_1, null);
      expect(standardId1).toEqual(standardId2);
    });

    it('should have same ID if given same external_uri (no name)', () => {
      const standardId1 = generateId(SC_1, null, URI_1);
      const standardId2 = generateId(SC_1, null, URI_1);
      expect(standardId1).toEqual(standardId2);
    });

    it('should have same ID if given same couple (name/external_uri)', () => {
      const standardId1 = generateId(SC_1, NAME_1, URI_1);
      const standardId2 = generateId(SC_1, NAME_1, URI_1);
      expect(standardId1).toEqual(standardId2);
    });
  });
});
