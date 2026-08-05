import { afterEach, describe, expect, it } from 'vitest';
import { addRelatedCoveredEntities } from '../../../../src/modules/securityCoverage/securityCoverageResult/securityCoverageResult-domain';
import { addSecurityCoverage, securityCoverageDelete } from '../../../../src/modules/securityCoverage/securityCoverage-domain';
import { addSecurityCoverageResult } from '../../../../src/modules/securityCoverage/securityCoverageResult/securityCoverageResult-domain';
import type { BasicStoreEntitySecurityCoverage } from '../../../../src/modules/securityCoverage/securityCoverage-types';
import { addReport, reportDeleteWithElements } from '../../../../src/domain/report';
import { addAttackPattern } from '../../../../src/domain/attackPattern';
import { addVulnerability } from '../../../../src/domain/vulnerability';
import { addIntrusionSet } from '../../../../src/domain/intrusionSet';
import { createRelation, deleteElementById } from '../../../../src/database/middleware';
import { fullRelationsList } from '../../../../src/database/middleware-loader';
import { RELATION_HAS_COVERED, RELATION_TARGETS, RELATION_USES } from '../../../../src/schema/stixCoreRelationship';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_VULNERABILITY } from '../../../../src/schema/stixDomainObject';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';

describe('Function: addRelatedCoveredEntities()', () => {
  let securityCoverage: BasicStoreEntitySecurityCoverage | undefined;

  afterEach(async () => {
    if (securityCoverage) {
      await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.id);
      securityCoverage = undefined;
    }
  });

  it('should create has-covered relationships for entities contained in a covered container', async () => {
    const attackPattern = await addAttackPattern(testContext, ADMIN_USER, { name: 'AP for addRelatedCoveredEntities test' });
    const vulnerability = await addVulnerability(testContext, ADMIN_USER, { name: 'Vuln for addRelatedCoveredEntities test' });
    const report = await addReport(testContext, ADMIN_USER, {
      name: 'Report for addRelatedCoveredEntities test',
      published: '2026-01-01T00:00:00.000Z',
      objects: [attackPattern.id, vulnerability.id],
    });

    securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, {
      name: 'SC container test',
      objectCovered: report.standard_id,
      auto_enrichment_disable: true,
    });
    const result = await addSecurityCoverageResult(testContext, ADMIN_USER, { resultOf: securityCoverage.id });

    const created = await addRelatedCoveredEntities(testContext, ADMIN_USER, result.id);
    expect(created.length).toEqual(2);

    const relations = await fullRelationsList(testContext, ADMIN_USER, RELATION_HAS_COVERED, { fromId: result.id });
    expect(relations.map((r) => r.toId).sort()).toEqual([attackPattern.id, vulnerability.id].sort());

    await deleteElementById(testContext, ADMIN_USER, attackPattern.id, ENTITY_TYPE_ATTACK_PATTERN);
    await deleteElementById(testContext, ADMIN_USER, vulnerability.id, ENTITY_TYPE_VULNERABILITY);
    await deleteElementById(testContext, ADMIN_USER, report.id, report.entity_type);
  });

  it('should create has-covered relationships for targeted/used entities of a covered non-container', async () => {
    const attackPattern = await addAttackPattern(testContext, ADMIN_USER, { name: 'AP for addRelatedCoveredEntities non-container test' });
    const vulnerability = await addVulnerability(testContext, ADMIN_USER, { name: 'Vuln for addRelatedCoveredEntities non-container test' });
    const intrusionSet = await addIntrusionSet(testContext, ADMIN_USER, { name: 'Intrusion set for addRelatedCoveredEntities test' });

    await createRelation(testContext, ADMIN_USER, {
      fromId: intrusionSet.id,
      toId: attackPattern.id,
      relationship_type: RELATION_USES,
    });
    await createRelation(testContext, ADMIN_USER, {
      fromId: intrusionSet.id,
      toId: vulnerability.id,
      relationship_type: RELATION_TARGETS,
    });

    securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, {
      name: 'SC non-container test',
      objectCovered: intrusionSet.standard_id,
      auto_enrichment_disable: true,
    });
    const result = await addSecurityCoverageResult(testContext, ADMIN_USER, { resultOf: securityCoverage.id });

    const created = await addRelatedCoveredEntities(testContext, ADMIN_USER, result.id);
    expect(created.length).toEqual(2);

    const relations = await fullRelationsList(testContext, ADMIN_USER, RELATION_HAS_COVERED, { fromId: result.id });
    expect(relations.map((r) => r.toId).sort()).toEqual([attackPattern.id, vulnerability.id].sort());

    await deleteElementById(testContext, ADMIN_USER, attackPattern.id, ENTITY_TYPE_ATTACK_PATTERN);
    await deleteElementById(testContext, ADMIN_USER, vulnerability.id, ENTITY_TYPE_VULNERABILITY);
    await deleteElementById(testContext, ADMIN_USER, intrusionSet.id, ENTITY_TYPE_INTRUSION_SET);
  });

  it('should throw a FunctionalError when no security coverage result is found for the given id', async () => {
    const fakeId = 'security-coverage-result--00000000-0000-0000-0000-000000000000';
    await expect(addRelatedCoveredEntities(testContext, ADMIN_USER, fakeId))
      .rejects.toThrow(`No security coverage result found for the id ${fakeId}`);
  });

  it('should throw a FunctionalError when the covered entity no longer exists', async () => {
    const report = await addReport(testContext, ADMIN_USER, {
      name: 'Report to delete for addRelatedCoveredEntities test',
      published: '2026-01-01T00:00:00.000Z',
    });

    securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, {
      name: 'SC dangling covered test',
      objectCovered: report.standard_id,
      auto_enrichment_disable: true,
    });
    const result = await addSecurityCoverageResult(testContext, ADMIN_USER, { resultOf: securityCoverage.id });

    await reportDeleteWithElements(testContext, ADMIN_USER, report.standard_id);

    await expect(addRelatedCoveredEntities(testContext, ADMIN_USER, result.id))
      .rejects.toThrow('No covered entity found for the id undefined');
  });
});
