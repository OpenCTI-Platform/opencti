import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { addSecurityCoverage, securityCoverageDelete } from '../../../../src/modules/securityCoverage/securityCoverage-domain';
import { addSecurityCoverageResult } from '../../../../src/modules/securityCoverage/securityCoverageResult/securityCoverageResult-domain';
import { addStixCoreRelationship } from '../../../../src/domain/stixCoreRelationship';
import { addAttackPattern } from '../../../../src/domain/attackPattern';
import { addReport, reportDeleteWithElements } from '../../../../src/domain/report';
import { stixDomainObjectDelete } from '../../../../src/domain/stixDomainObject';
import { ENTITY_TYPE_ATTACK_PATTERN } from '../../../../src/schema/stixDomainObject';
import { findVocabularyPaginated, getVocabularyUsages } from '../../../../src/modules/vocabulary/vocabulary-domain';
import { VocabularyCategory } from '../../../../src/generated/graphql';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import type { BasicStoreEntityVocabulary } from '../../../../src/modules/vocabulary/vocabulary-types';
import type { StoreEntityReport } from '../../../../src/types/store';

describe('Vocabulary usages: coverage_ov (composite field coverage_information.coverage_name)', () => {
  let report: StoreEntityReport;
  let securityCoverageId: string;
  let attackPatternId: string;
  let detection: BasicStoreEntityVocabulary;
  let prevention: BasicStoreEntityVocabulary;

  const loadVocabulary = async (name: string) => {
    const page = await findVocabularyPaginated(testContext, ADMIN_USER, { category: VocabularyCategory.CoverageOv, first: 100 });
    return page.edges.map((edge) => edge.node).find((node) => node.name === name) as BasicStoreEntityVocabulary;
  };

  beforeAll(async () => {
    detection = await loadVocabulary('detection');
    prevention = await loadVocabulary('prevention');
    report = await addReport(testContext, ADMIN_USER, { name: 'Report for vocabulary usages test', published: '2026-04-24T19:15:00.000Z' });
    const created = await addSecurityCoverage(testContext, ADMIN_USER, { name: 'sc vocabulary usages', objectCovered: report.standard_id, auto_enrichment_disable: true });
    securityCoverageId = created.id;
    const result = await addSecurityCoverageResult(testContext, ADMIN_USER, { name: 'OAEV vocabulary usages', resultOf: created.id });
    const attackPattern = await addAttackPattern(testContext, ADMIN_USER, { name: 'Tested vocabulary usages' });
    attackPatternId = attackPattern.id;
    await addStixCoreRelationship(testContext, ADMIN_USER, {
      fromId: result.id,
      toId: attackPattern.id,
      relationship_type: 'has-covered',
      coverage_information: [{ coverage_name: 'detection', coverage_score: 10 }],
    });
  });

  afterAll(async () => {
    await securityCoverageDelete(testContext, ADMIN_USER, securityCoverageId);
    await stixDomainObjectDelete(testContext, ADMIN_USER, attackPatternId, ENTITY_TYPE_ATTACK_PATTERN);
    await reportDeleteWithElements(testContext, ADMIN_USER, report.standard_id);
  });

  it('counts the entities carrying the value in a coverage entry, without throwing', async () => {
    expect(detection).toBeDefined();
    const usages = await getVocabularyUsages(testContext, ADMIN_USER, detection);
    expect(usages).toBeGreaterThanOrEqual(1);
  });
  it('does not count a value no coverage entry carries', async () => {
    expect(prevention).toBeDefined();
    expect(await getVocabularyUsages(testContext, ADMIN_USER, prevention)).toBe(0);
  });
});
