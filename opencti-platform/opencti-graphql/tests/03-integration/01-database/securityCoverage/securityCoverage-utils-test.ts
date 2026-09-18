import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { transformHasCoveredFromId } from '../../../../src/modules/securityCoverage/securityCoverage-utils';
import { SYSTEM_USER } from '../../../../src/utils/access';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { addSecurityCoverage, listSecurityCoverageResults, securityCoverageDelete } from '../../../../src/modules/securityCoverage/securityCoverage-domain';
import type { BasicStoreEntitySecurityCoverage } from '../../../../src/modules/securityCoverage/securityCoverage-types';
import type { BasicStoreEntitySecurityCoverageResult } from '../../../../src/modules/securityCoverage/securityCoverageResult/securityCoverageResult-types';
import { addAttackPattern } from '../../../../src/domain/attackPattern';
import { addIntrusionSet } from '../../../../src/domain/intrusionSet';
import { addReport, reportDeleteWithElements } from '../../../../src/domain/report';
import { stixDomainObjectDelete, stixDomainObjectDeleteRelation } from '../../../../src/domain/stixDomainObject';
import { addStixCoreRelationship, stixCoreRelationshipDelete } from '../../../../src/domain/stixCoreRelationship';
import { fullRelationsList, storeLoadById } from '../../../../src/database/middleware-loader';
import { RELATION_HAS_COVERED, RELATION_USES } from '../../../../src/schema/stixCoreRelationship';
import { RELATION_OBJECT } from '../../../../src/schema/stixRefRelationship';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_INTRUSION_SET } from '../../../../src/schema/stixDomainObject';
import type { BasicStoreEntity, BasicStoreRelation, StoreEntityReport } from '../../../../src/types/store';

describe('Function transformHasCoveredFromId', () => {
  let securityCoverage: BasicStoreEntitySecurityCoverage;
  let result: BasicStoreEntitySecurityCoverageResult;

  beforeEach(async () => {
    securityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, {
      name: 'sc1',
      objectCovered: 'report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7',
      auto_enrichment_disable: true,
      external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a999',
    });
    result = (await listSecurityCoverageResults(testContext, ADMIN_USER, securityCoverage))[0];
  });

  afterEach(async () => {
    await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.standard_id);
  });

  it('should replace security coverage id by security coverage result id when valid external_uri', async () => {
    const newInput = await transformHasCoveredFromId(
      testContext,
      SYSTEM_USER,
      {
        relationship_type: 'has-covered',
        external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a999',
        fromId: securityCoverage.standard_id,
        toId: 'attack-pattern--2fc04aa5-48c1-49ec-919a-b88241ef1d17',
      },
    );
    expect(newInput).toEqual({
      relationship_type: 'has-covered',
      external_uri: 'http://localhost/admin/scenarios/a2166709-be41-48bf-9ce1-51bb2fd3a999',
      fromId: result.standard_id,
      toId: 'attack-pattern--2fc04aa5-48c1-49ec-919a-b88241ef1d17',
    });
  });

  it('should throw an error if invalid external uri', async () => {
    const call = () => transformHasCoveredFromId(
      testContext,
      SYSTEM_USER,
      {
        relationship_type: 'has-covered',
        external_uri: 'http://192.168.1.150:8080/admin/scenarios/hello-there',
        fromId: 'security-coverage--c76bfcfe-2be5-500f-9b81-367457f1088f',
        toId: 'attack-pattern--2fc04aa5-48c1-49ec-919a-b88241ef1d17',
      },
    );
    await expect(call()).rejects.toThrow('Cannot find SecurityCoverageResult for this has-covered relationship');
  });

  it('should replace security coverage id by security coverage result id when no external_uri', async () => {
    const newInput = await transformHasCoveredFromId(
      testContext,
      SYSTEM_USER,
      {
        relationship_type: 'has-covered',
        fromId: securityCoverage.standard_id,
        toId: 'attack-pattern--2fc04aa5-48c1-49ec-919a-b88241ef1d17',
      },
    );
    expect(newInput).toEqual({
      relationship_type: 'has-covered',
      fromId: result.standard_id,
      toId: 'attack-pattern--2fc04aa5-48c1-49ec-919a-b88241ef1d17',
    });
  });
});

describe('Security coverage has-covered cleanup when an entity leaves the covered scope', () => {
  const createAttackPatterns = async (prefix: string) => {
    const attackPatterns: BasicStoreEntity[] = [];
    for (const suffix of ['AP1', 'AP2', 'AP3']) {
      attackPatterns.push(await addAttackPattern(testContext, ADMIN_USER, { name: `${prefix} ${suffix}` }));
    }
    return attackPatterns;
  };

  // The coverage result covers every attack pattern of the assessed scope, as OpenAEV would report it.
  const createCoverageCoveringAll = async (prefix: string, coveredStandardId: string, attackPatterns: BasicStoreEntity[]) => {
    const securityCoverage: BasicStoreEntitySecurityCoverage = await addSecurityCoverage(testContext, ADMIN_USER, {
      name: `${prefix} coverage`,
      objectCovered: coveredStandardId,
      auto_enrichment_disable: true,
      external_uri: `http://localhost/admin/scenarios/${prefix}`,
    });
    const result = (await listSecurityCoverageResults(testContext, ADMIN_USER, securityCoverage))[0];
    for (const attackPattern of attackPatterns) {
      await addStixCoreRelationship(testContext, ADMIN_USER, {
        fromId: result.standard_id,
        toId: attackPattern.standard_id,
        relationship_type: RELATION_HAS_COVERED,
      });
    }
    return { securityCoverage, result };
  };

  const deleteAttackPatterns = async (attackPatterns: BasicStoreEntity[]) => {
    for (const attackPattern of attackPatterns) {
      await stixDomainObjectDelete(testContext, ADMIN_USER, attackPattern.id, ENTITY_TYPE_ATTACK_PATTERN);
    }
  };

  const listCoveredTargetIds = async (resultId: string) => {
    const relations = await fullRelationsList<BasicStoreRelation>(testContext, ADMIN_USER, RELATION_HAS_COVERED, { fromId: resultId });
    return relations.map((relation) => relation.toId).sort();
  };

  const sortedIds = (attackPatterns: BasicStoreEntity[]) => attackPatterns.map((attackPattern) => attackPattern.internal_id).sort();

  it('should remove the has-covered of an entity removed from a covered report, keeping the other ones', async () => {
    const prefix = 'sc-cleanup-report';
    const attackPatterns = await createAttackPatterns(prefix);
    const report: StoreEntityReport = await addReport(testContext, ADMIN_USER, {
      name: `${prefix} report`,
      published: '2026-04-24T19:15:00.000Z',
      objects: attackPatterns.map((attackPattern) => attackPattern.standard_id),
    });
    const { securityCoverage, result } = await createCoverageCoveringAll(prefix, report.standard_id, attackPatterns);
    expect(await listCoveredTargetIds(result.id)).toEqual(sortedIds(attackPatterns));

    const [removed, ...stillInReport] = attackPatterns;
    await stixDomainObjectDeleteRelation(testContext, ADMIN_USER, report.internal_id, removed.id, RELATION_OBJECT);

    expect(await listCoveredTargetIds(result.id)).toEqual(sortedIds(stillInReport));
    // The entity is only removed from the report, it must still exist
    expect(await storeLoadById(testContext, ADMIN_USER, removed.id, ENTITY_TYPE_ATTACK_PATTERN)).toBeDefined();

    await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.standard_id);
    await reportDeleteWithElements(testContext, ADMIN_USER, report.standard_id);
    await deleteAttackPatterns(attackPatterns);
  });

  it('should remove the has-covered of an entity unlinked from a covered intrusion set, keeping the other ones', async () => {
    const prefix = 'sc-cleanup-intrusion-set';
    const attackPatterns = await createAttackPatterns(prefix);
    const intrusionSet: BasicStoreEntity = await addIntrusionSet(testContext, ADMIN_USER, { name: `${prefix} intrusion set` });
    const usesRelations = [];
    for (const attackPattern of attackPatterns) {
      usesRelations.push(await addStixCoreRelationship(testContext, ADMIN_USER, {
        fromId: intrusionSet.standard_id,
        toId: attackPattern.standard_id,
        relationship_type: RELATION_USES,
      }));
    }
    const { securityCoverage, result } = await createCoverageCoveringAll(prefix, intrusionSet.standard_id, attackPatterns);
    expect(await listCoveredTargetIds(result.id)).toEqual(sortedIds(attackPatterns));

    const [removed, ...stillUsed] = attackPatterns;
    await stixCoreRelationshipDelete(testContext, ADMIN_USER, usesRelations[0].id);

    expect(await listCoveredTargetIds(result.id)).toEqual(sortedIds(stillUsed));
    expect(await storeLoadById(testContext, ADMIN_USER, removed.id, ENTITY_TYPE_ATTACK_PATTERN)).toBeDefined();

    await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.standard_id);
    await stixDomainObjectDelete(testContext, ADMIN_USER, intrusionSet.id, ENTITY_TYPE_INTRUSION_SET);
    await deleteAttackPatterns(attackPatterns);
  });
});
