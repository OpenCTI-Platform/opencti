import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  addSecurityCoverage,
  listSecurityCoverageResults,
  securityCoverageDelete,
  securityCoverageStixBundle,
} from '../../../../src/modules/securityCoverage/securityCoverage-domain';
import { createHasCoveredRelTask } from '../../../../src/modules/securityCoverage/securityCoverageResult/securityCoverageResult-domain';
import { addAttackPattern } from '../../../../src/domain/attackPattern';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { addReport, reportDeleteWithElements } from '../../../../src/domain/report';
import { stixDomainObjectDelete } from '../../../../src/domain/stixDomainObject';
import { ENTITY_TYPE_ATTACK_PATTERN } from '../../../../src/schema/stixDomainObject';
import type { StoreEntityReport } from '../../../../src/types/store';
import type { StixSecurityCoverage } from '../../../../src/modules/securityCoverage/securityCoverage-types';
import { findBackgroundTaskPaginated } from '../../../../src/domain/backgroundTask';

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
    it('should create coverage result if explicitly asked for', async () => {
      const input = {
        ...BASE_INPUT(),
        add_all_related_entities: true,
      };
      const securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, input);
      const results = await listSecurityCoverageResults(testContext, ADMIN_USER, securityCoverage);
      expect(results.length).toEqual(1);
      // Name should be the external_uri when it is defined
      expect(results[0].name).toEqual('Result of sc1');
      await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.id);
    });

    it('should create coverage result if entities_to_add is provided without add_all_related_entities', async () => {
      const input = {
        ...BASE_INPUT(),
        entities_to_add: ['attack-pattern--00000000-0000-0000-0000-000000000001'],
      };
      const securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, input);
      const results = await listSecurityCoverageResults(testContext, ADMIN_USER, securityCoverage);
      expect(results.length).toEqual(1);
      await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.id);
    });

    it('should create coverage result if contains eternal uri', async () => {
      const externalUri = 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a131';
      const input = {
        ...BASE_INPUT(),
        coverage_information: [{
          coverage_name: 'prevention',
          coverage_score: 10,
        }],
        external_uri: externalUri,
      };
      const securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, input);
      const results = await listSecurityCoverageResults(testContext, ADMIN_USER, securityCoverage);
      expect(results.length).toEqual(1);
      // Name should be the external_uri when it is defined
      expect(results[0].name).toEqual(`${externalUri} Result of sc1`);
      await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.id);
    });

    it('should create coverage result if contains external_uri without coverage info', async () => {
      const input = {
        ...BASE_INPUT(),
        tenant_name: 'Super Coverage',
        external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a132',
      };
      const securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, input);
      const results = await listSecurityCoverageResults(testContext, ADMIN_USER, securityCoverage);
      expect(results.length).toEqual(1);
      // Name should be the tenant_name when it is defined
      expect(results[0].name).toEqual('Super Coverage Result of sc1');
      await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.id);
    });

    it('should not create coverage result if no manual neither external_uri', async () => {
      const input = {
        ...BASE_INPUT(),
      };
      const securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, input);
      const results = await listSecurityCoverageResults(testContext, ADMIN_USER, securityCoverage);
      expect(results.length).toEqual(0);
      await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.id);
    });
  });

  describe('Function securityCoverageStixBundle()', () => {
    it('should return a bundle containing the coverage and the covered entity', async () => {
      const input = {
        ...BASE_INPUT(),
        name: 'sc to export',
        coverage_information: [{
          coverage_name: 'prevention',
          coverage_score: 10,
        }],
      };
      const securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, input);
      const bundle = JSON.parse(await securityCoverageStixBundle(testContext, ADMIN_USER, securityCoverage.id));
      const bundleObjects = bundle.objects as unknown as StixSecurityCoverage[];

      const stixCoverage = bundleObjects.find((o) => o.type === 'security-coverage');
      expect(stixCoverage?.id).toEqual(securityCoverage.standard_id);
      expect(stixCoverage?.covered_ref).toEqual(report.standard_id);
      // The covered entity must be exported as a distinct object of the bundle
      expect(bundleObjects.filter((o) => o.id === report.standard_id).length).toEqual(1);

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
        add_all_related_entities: true,
      };
      const securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, input);
      let results = await listSecurityCoverageResults(testContext, ADMIN_USER, securityCoverage);
      expect(results.length).toEqual(1);
      // Name falls back to "Result of <name>" when no external_uri is provided
      expect(results[0].name).toEqual(`Result of ${securityCoverage.name}`);
      await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.id);
      results = await listSecurityCoverageResults(testContext, ADMIN_USER, securityCoverage);
      expect(results.length).toEqual(0);
    });
  });

  describe('Function createHasCoveredRelTask() with explicit entity selection', () => {
    it('should only target explicit entities_to_add ids, ignoring the rest of the related entities', async () => {
      const attackPattern1 = await addAttackPattern(testContext, ADMIN_USER, { name: 'SC entities_to_add AP1' });
      const attackPattern2 = await addAttackPattern(testContext, ADMIN_USER, { name: 'SC entities_to_add AP2' });
      const attackPattern3 = await addAttackPattern(testContext, ADMIN_USER, { name: 'SC entities_to_add AP3' });
      const reportWithTargets = await addReport(testContext, ADMIN_USER, {
        name: 'Report for SC entities_to_add test',
        published: '2026-04-24T19:15:00.000Z',
        objects: [attackPattern1.standard_id, attackPattern2.standard_id, attackPattern3.standard_id],
      });

      const input = {
        ...BASE_INPUT(),
        objectCovered: reportWithTargets.standard_id,
        external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a199',
      };
      const securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, input);
      const results = await listSecurityCoverageResults(testContext, ADMIN_USER, securityCoverage);
      expect(results.length).toEqual(1);

      const explicitIds = [attackPattern1.standard_id, attackPattern2.standard_id];
      const task = await createHasCoveredRelTask(testContext, ADMIN_USER, results[0].id, explicitIds);
      expect(task.task_ids).toEqual(explicitIds);
      expect(task.task_ids.length).toBeLessThan(3);

      await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.id);
      await reportDeleteWithElements(testContext, ADMIN_USER, reportWithTargets.standard_id);
      for (const attackPattern of [attackPattern1, attackPattern2, attackPattern3]) {
        await stixDomainObjectDelete(testContext, ADMIN_USER, attackPattern.id, ENTITY_TYPE_ATTACK_PATTERN);
      }
    });
  });

  describe('Function addSecurityCoverage() end-to-end wiring with entities_to_add', () => {
    const findHasCoveredRelTask = async (securityCoverageResultId: string) => {
      const taskConnection = await findBackgroundTaskPaginated(testContext, ADMIN_USER, {
        orderBy: 'created_at',
        orderMode: 'desc',
        first: 50,
      });
      const task = taskConnection.edges
        .map((edge: { node: { description?: string; task_ids?: string[] } }) => edge.node)
        .find((node: { description?: string }) => (node.description ?? '').includes(securityCoverageResultId));
      if (!task) {
        throw new Error(`No background task found for security coverage result ${securityCoverageResultId}`);
      }
      return task as { description?: string; task_ids: string[] };
    };

    const setupReportWithAttackPatterns = async (namePrefix: string) => {
      const attackPattern1 = await addAttackPattern(testContext, ADMIN_USER, { name: `${namePrefix} AP1` });
      const attackPattern2 = await addAttackPattern(testContext, ADMIN_USER, { name: `${namePrefix} AP2` });
      const attackPattern3 = await addAttackPattern(testContext, ADMIN_USER, { name: `${namePrefix} AP3` });
      const reportWithTargets = await addReport(testContext, ADMIN_USER, {
        name: `Report for ${namePrefix}`,
        published: '2026-04-24T19:15:00.000Z',
        objects: [attackPattern1.standard_id, attackPattern2.standard_id, attackPattern3.standard_id],
      });
      return {
        attackPattern1, attackPattern2, attackPattern3, reportWithTargets,
      };
    };

    const cleanup = async (
      securityCoverageId: string,
      reportWithTargets: StoreEntityReport,
      attackPatterns: Array<{ id: string }>,
    ) => {
      await securityCoverageDelete(testContext, ADMIN_USER, securityCoverageId);
      await reportDeleteWithElements(testContext, ADMIN_USER, reportWithTargets.standard_id);
      for (const attackPattern of attackPatterns) {
        await stixDomainObjectDelete(testContext, ADMIN_USER, attackPattern.id, ENTITY_TYPE_ATTACK_PATTERN);
      }
    };

    it('should create a background task targeting only entities_to_add when called through addSecurityCoverage', async () => {
      const {
        attackPattern1, attackPattern2, attackPattern3, reportWithTargets,
      } = await setupReportWithAttackPatterns('SC e2e entities_to_add');

      const input = {
        ...BASE_INPUT(),
        objectCovered: reportWithTargets.standard_id,
        entities_to_add: [attackPattern1.standard_id, attackPattern2.standard_id],
      };
      const securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, input);
      const results = await listSecurityCoverageResults(testContext, ADMIN_USER, securityCoverage);
      expect(results.length).toEqual(1);

      const task = await findHasCoveredRelTask(results[0].id);
      expect(task.task_ids).toEqual([attackPattern1.standard_id, attackPattern2.standard_id]);

      await cleanup(securityCoverage.id, reportWithTargets, [attackPattern1, attackPattern2, attackPattern3]);
    });

    it('should give precedence to add_all_related_entities over entities_to_add when both are provided', async () => {
      const {
        attackPattern1, attackPattern2, attackPattern3, reportWithTargets,
      } = await setupReportWithAttackPatterns('SC e2e precedence');

      const input = {
        ...BASE_INPUT(),
        objectCovered: reportWithTargets.standard_id,
        add_all_related_entities: true,
        entities_to_add: [attackPattern1.standard_id],
      };
      const securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, input);
      const results = await listSecurityCoverageResults(testContext, ADMIN_USER, securityCoverage);
      expect(results.length).toEqual(1);

      const task = await findHasCoveredRelTask(results[0].id);
      expect(task.task_ids.length).toEqual(3);
      expect(task.task_ids).toEqual(expect.arrayContaining([
        attackPattern1.id,
        attackPattern2.id,
        attackPattern3.id,
      ]));

      await cleanup(securityCoverage.id, reportWithTargets, [attackPattern1, attackPattern2, attackPattern3]);
    });
  });
});
