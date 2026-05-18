import { describe, expect, it } from 'vitest';
import { ENTITY_TYPE_SECURITY_COVERAGE_RESULT } from '../../../../src/modules/securityCoverage/securityCoverageResult/securityCoverageResult-types';
import { generateStandardId } from '../../../../src/schema/identifier';

describe('SecurityCoverageResult identifier', () => {
  const generateId = (data: any) => generateStandardId(
    ENTITY_TYPE_SECURITY_COVERAGE_RESULT,
    {
      resultOf: { standard_id: 'security-coverage-1232121a12e' },
      ...data,
    },
  );

  it('should throw an error if no data given', () => {});

  describe('using same ref resultOf', () => {
    it('should have same ID if given same name (no external_uri)', () => {
      const standardId1 = generateId({
        name: 'My security coverage',
      });
      const standardId2 = generateId({
        name: 'My security coverage',
      });
      expect(standardId1).toEqual(standardId2);
    });

    it('should have different ID if given different name (no external_uri)', () => {
      const standardId1 = generateId({
        name: 'My security coverage',
      });
      const standardId2 = generateId({
        name: 'My security coverage bis',
      });
      expect(standardId1).not.toEqual(standardId2);
    });

    it('should have same ID if given same external_uri (no name)', () => {
      const standardId1 = generateId({
        external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a131',
      });
      const standardId2 = generateId({
        external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a131',
      });
      expect(standardId1).toEqual(standardId2);
    });

    it('should have different ID if given different external_uri (no name)', () => {
      const standardId1 = generateId({
        external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a131',
      });
      const standardId2 = generateId({
        external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd35294',
      });
      expect(standardId1).not.toEqual(standardId2);
    });

    it('should have same ID if given same couple (name/external_uri)', () => {
      const standardId1 = generateId({
        name: 'Super result',
        external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a131',
      });
      const standardId2 = generateId({
        name: 'Super result',
        external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a131',
      });
      expect(standardId1).toEqual(standardId2);
    });

    it('should have different ID if given same name but different external_uri', () => {
      const standardId1 = generateId({
        name: 'Super result',
        external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a131',
      });
      const standardId2 = generateId({
        name: 'Super result',
        external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd39375',
      });
      expect(standardId1).not.toEqual(standardId2);
    });

    it('should have different ID if given same external_uri but different name', () => {
      const standardId1 = generateId({
        name: 'Super result',
        external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a131',
      });
      const standardId2 = generateId({
        name: 'Super coverage result',
        external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a131',
      });
      expect(standardId1).not.toEqual(standardId2);
    });

    it('should have different ID if given different external_uri but different name', () => {
      const standardId1 = generateId({
        name: 'Super result',
        external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a131',
      });
      const standardId2 = generateId({
        name: 'Super result bis',
        external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd37351',
      });
      expect(standardId1).not.toEqual(standardId2);
    });
  });

  describe('using different ref resultOf', () => {
    it('should have different ID with same name but different ref', () => {
      const standardId1 = generateId({
        name: 'Super result',
      });
      const standardId2 = generateId({
        name: 'Super result',
        resultOf: { standard_id: 'security-coverage-1232121472165' },
      });
      expect(standardId1).not.toEqual(standardId2);
    });

    it('should have different ID with same external_uri but different ref', () => {
      const standardId1 = generateId({
        external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a131',
      });
      const standardId2 = generateId({
        external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd39375',
        resultOf: { standard_id: 'security-coverage-1232121472165' },
      });
      expect(standardId1).not.toEqual(standardId2);
    });
  });
});
