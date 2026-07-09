import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { addSecurityCoverage, securityCoverageDelete } from '../../../../src/modules/securityCoverage/securityCoverage-domain';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { addReport, reportDeleteWithElements } from '../../../../src/domain/report';
import type { StoreEntityReport } from '../../../../src/types/store';
import { loadThroughDenormalized } from '../../../../src/resolvers/stix';
import { INPUT_RESULT_OF } from '../../../../src/modules/securityCoverage/securityCoverageResult/securityCoverageResult-types';

describe('SecurityCoverage domain', () => {
  let report: StoreEntityReport;

  const BASE_INPUT = () => ({
    name: 'sc1',
    objectCovered: report.standard_id,
    auto_enrichment_disable: true,
  });

  beforeAll(async () => {
    report = await addReport(testContext, ADMIN_USER, {
      name: 'Report for SC tests',
      published: '2026-04-24T19:15:00.000Z',
    });
  });

  afterAll(async () => {
    await reportDeleteWithElements(testContext, ADMIN_USER, report.standard_id);
  });

  describe('Function addSecurityCoverage()', () => {
    it('should create coverage result if contains coverage information', async () => {
      const input = {
        ...BASE_INPUT(),
        coverage_information: [{
          coverage_name: 'prevention',
          coverage_score: 10,
        }],
        external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a131',
      };
      const securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, input);
      const results = await loadThroughDenormalized(testContext, ADMIN_USER, securityCoverage, INPUT_RESULT_OF);
      expect(results.length).toEqual(1);
      await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.id);
    });

    it('should create coverage result if contains no information but external_uri', async () => {
      const input = {
        ...BASE_INPUT(),
        external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a132',
      };
      const securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, input);
      const results = await loadThroughDenormalized(testContext, ADMIN_USER, securityCoverage, INPUT_RESULT_OF);
      expect(results.length).toEqual(1);
      await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.id);
    });

    it('should not create coverage result if no coverage info neither external_uri', async () => {
      const input = {
        ...BASE_INPUT(),
      };
      const securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, input);
      const results = await loadThroughDenormalized(testContext, ADMIN_USER, securityCoverage, INPUT_RESULT_OF);
      expect(results.length).toEqual(0);
      await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.id);
    });
  });

  describe('Function securityCoverageDelete()', () => {
    it('should delete security coverage results when deleting a security coverage', async () => {
      const input = {
        ...BASE_INPUT(),
        name: 'sc to delete',
        coverage_information: [{
          coverage_name: 'prevention',
          coverage_score: 10,
        }],
      };
      const securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, input);
      let results = await loadThroughDenormalized(testContext, ADMIN_USER, securityCoverage, INPUT_RESULT_OF);
      expect(results.length).toEqual(1);
      await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.id);
      results = await loadThroughDenormalized(testContext, ADMIN_USER, securityCoverage, INPUT_RESULT_OF);
      expect(results.length).toEqual(0);
    });
  });
});
