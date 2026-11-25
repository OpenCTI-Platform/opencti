import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PLAYBOOK_COMPONENTS } from '../../../../../src/modules/playbook/playbook-components';
import { stixLoadById } from '../../../../../src/database/middleware';
import { ADMIN_USER, testContext } from '../../../../utils/testQuery';
import type { StixSighting } from '../../../../../src/types/stix-2-1-sro';
import type { StixObject } from '../../../../../src/types/stix-2-1-common';
import { testExecutor } from './playbook-components-test-utils';
import { addReport, reportDeleteWithElements } from '../../../../../src/domain/report';
import { addSecurityCoverage, securityCoverageDelete } from '../../../../../src/modules/securityCoverage/securityCoverage-domain';
import { addSecurityCoverageResult } from '../../../../../src/modules/securityCoverage/securityCoverageResult/securityCoverageResult-domain';
import { addAttackPattern } from '../../../../../src/domain/attackPattern';
import { addStixCoreRelationship } from '../../../../../src/domain/stixCoreRelationship';
import { stixDomainObjectDelete } from '../../../../../src/domain/stixDomainObject';
import { ENTITY_TYPE_ATTACK_PATTERN } from '../../../../../src/schema/stixDomainObject';
import type { StoreEntityReport } from '../../../../../src/types/store';

const PLAYBOOK_RULE_COMPONENT = PLAYBOOK_COMPONENTS.PLAYBOOK_RULE_COMPONENT;

describe('PLAYBOOK_RULE_COMPONENT', () => {
  describe('resolve_neighbors', () => {
    it('should resolve sighting_of and where_sighted of a sighting', async () => {
      const sighting = await stixLoadById(testContext, ADMIN_USER, 'sighting--ee20065d-2555-424f-ad9e-0f8428623c75') as StixSighting;
      expect(sighting).toBeDefined();
      const result = await PLAYBOOK_RULE_COMPONENT.executor(testExecutor({
        mainId: sighting.id,
        bundleObjects: [sighting],
        configuration: { rule: 'resolve_neighbors', inferences: false },
      }));

      expect(result.output_port).toEqual('out');
      const resultIds = result.bundle.objects.map((o) => o.id);
      expect(resultIds).toContain(sighting.sighting_of_ref);
      sighting.where_sighted_refs.forEach((whereSightedRef) => {
        expect(resultIds).toContain(whereSightedRef);
      });
    });
  });

  describe('resolve_neighbors on security coverages', () => {
    // A security coverage is identified by its covered entity: each coverage gets its own report.
    const adminContext = { ...testContext, user: ADMIN_USER };
    const configuration = { rule: 'resolve_neighbors', inferences: false };
    let coveredReport: StoreEntityReport;
    let emptyCoveredReport: StoreEntityReport;
    let securityCoverageId: string;
    let emptySecurityCoverageId: string;
    let resultOne: { id: string; standard_id: string };
    let resultTwo: { id: string; standard_id: string };
    const attackPatterns: { id: string; standard_id: string }[] = [];
    const hasCoveredIds: string[] = [];

    const addHasCovered = async (result: { id: string }, name: string) => {
      const attackPattern = await addAttackPattern(testContext, ADMIN_USER, { name });
      attackPatterns.push(attackPattern);
      const hasCovered = await addStixCoreRelationship(testContext, ADMIN_USER, {
        fromId: result.id,
        toId: attackPattern.id,
        relationship_type: 'has-covered',
        coverage_information: [{ coverage_name: 'detection', coverage_score: 50 }],
      });
      hasCoveredIds.push(hasCovered.standard_id);
    };

    const runRule = async (mainId: string) => {
      const main = await stixLoadById(testContext, ADMIN_USER, mainId) as StixObject;
      return PLAYBOOK_RULE_COMPONENT.executor(testExecutor({ mainId: main.id, bundleObjects: [main], configuration }));
    };

    beforeAll(async () => {
      coveredReport = await addReport(testContext, ADMIN_USER, { name: 'Report covered for resolve neighbors', published: '2026-11-25T10:00:00.000Z' });
      emptyCoveredReport = await addReport(testContext, ADMIN_USER, { name: 'Report covered without result', published: '2026-11-25T10:00:00.000Z' });
      const securityCoverage = await addSecurityCoverage(adminContext, ADMIN_USER, { name: 'sc resolve neighbors', objectCovered: coveredReport.standard_id, auto_enrichment_disable: true });
      securityCoverageId = securityCoverage.id;
      const emptySecurityCoverage = await addSecurityCoverage(adminContext, ADMIN_USER, { name: 'sc without result', objectCovered: emptyCoveredReport.standard_id, auto_enrichment_disable: true });
      emptySecurityCoverageId = emptySecurityCoverage.id;
      resultOne = await addSecurityCoverageResult(adminContext, ADMIN_USER, { name: 'OAEV neighbors one', resultOf: securityCoverageId });
      resultTwo = await addSecurityCoverageResult(adminContext, ADMIN_USER, { name: 'OAEV neighbors two', resultOf: securityCoverageId });
      await addHasCovered(resultOne, 'Resolve neighbors covered one');
      await addHasCovered(resultTwo, 'Resolve neighbors covered two');
    });

    afterAll(async () => {
      // Deleting a coverage deletes its results, and their has-covered relationships with them.
      await securityCoverageDelete(testContext, ADMIN_USER, securityCoverageId);
      await securityCoverageDelete(testContext, ADMIN_USER, emptySecurityCoverageId);
      for (const attackPattern of attackPatterns) {
        await stixDomainObjectDelete(testContext, ADMIN_USER, attackPattern.id, ENTITY_TYPE_ATTACK_PATTERN);
      }
      await reportDeleteWithElements(testContext, ADMIN_USER, coveredReport.standard_id);
      await reportDeleteWithElements(testContext, ADMIN_USER, emptyCoveredReport.standard_id);
    });

    it('should resolve the results of a security coverage, their has-covered and the covered targets', async () => {
      const result = await runRule(securityCoverageId);

      expect(result.output_port).toEqual('out');
      const resultIds = result.bundle.objects.map((o) => o.id);
      [resultOne.standard_id, resultTwo.standard_id, ...hasCoveredIds, ...attackPatterns.map((a) => a.standard_id)].forEach((expectedId) => {
        expect(resultIds).toContain(expectedId);
      });
      // The covered entity is not a neighbor: sharing the bundle must not share it.
      expect(resultIds).not.toContain(coveredReport.standard_id);
    });

    it('should resolve the parent security coverage of a security coverage result', async () => {
      const result = await runRule(resultOne.id);

      expect(result.output_port).toEqual('out');
      const resultIds = result.bundle.objects.map((o) => o.id);
      const securityCoverage = await stixLoadById(testContext, ADMIN_USER, securityCoverageId) as StixObject;
      expect(resultIds).toContain(securityCoverage.id);
      expect(resultIds).toContain(hasCoveredIds[0]);
      expect(resultIds).toContain(attackPatterns[0].standard_id);
    });

    it('should leave a security coverage without result unmodified', async () => {
      const result = await runRule(emptySecurityCoverageId);

      expect(result.output_port).toEqual('unmodified');
      expect(result.bundle.objects.length).toEqual(1);
    });
  });
});
