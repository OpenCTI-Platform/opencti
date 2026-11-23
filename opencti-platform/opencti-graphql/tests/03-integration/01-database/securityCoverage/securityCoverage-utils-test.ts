import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { transformHasCoveredFromId } from '../../../../src/modules/securityCoverage/securityCoverage-utils';
import { SYSTEM_USER } from '../../../../src/utils/access';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { addSecurityCoverage, listSecurityCoverageResults, securityCoverageDelete } from '../../../../src/modules/securityCoverage/securityCoverage-domain';
import type { BasicStoreEntitySecurityCoverage } from '../../../../src/modules/securityCoverage/securityCoverage-types';
import type { BasicStoreEntitySecurityCoverageResult } from '../../../../src/modules/securityCoverage/securityCoverageResult/securityCoverageResult-types';
import { addAttackPattern } from '../../../../src/domain/attackPattern';
import { addCampaign } from '../../../../src/domain/campaign';
import { addIntrusionSet } from '../../../../src/domain/intrusionSet';
import { addReport } from '../../../../src/domain/report';
import { stixDomainObjectAddRelation, stixDomainObjectDelete, stixDomainObjectDeleteRelation, stixDomainObjectEditField } from '../../../../src/domain/stixDomainObject';
import { addStixCoreRelationship, stixCoreRelationshipDelete, stixCoreRelationshipDeleteByFromAndTo } from '../../../../src/domain/stixCoreRelationship';
import { fullRelationsList, storeLoadById } from '../../../../src/database/middleware-loader';
import { deleteElementById, storeLoadByIdWithRefs } from '../../../../src/database/middleware';
import { addDraftWorkspace } from '../../../../src/modules/draftWorkspace/draftWorkspace-domain';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../../../../src/modules/draftWorkspace/draftWorkspace-types';
import type { AuthContext } from '../../../../src/types/user';
import { RELATION_HAS_COVERED, RELATION_TARGETS, RELATION_USES } from '../../../../src/schema/stixCoreRelationship';
import { RELATION_CREATED_BY, RELATION_OBJECT } from '../../../../src/schema/stixRefRelationship';
import { addOrganization } from '../../../../src/modules/organization/organization-domain';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../../src/modules/organization/organization-types';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_CAMPAIGN, ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_INTRUSION_SET } from '../../../../src/schema/stixDomainObject';
import type { BasicStoreEntity, BasicStoreRelation, StoreEntityReport } from '../../../../src/types/store';
import { addVulnerability } from '../../../../src/modules/vulnerability/vulnerability-domain';
import { ENTITY_TYPE_VULNERABILITY } from '../../../../src/modules/vulnerability/vulnerability-types';
import { INPUT_OBJECTS } from '../../../../src/schema/general';
import { EditOperation } from '../../../../src/generated/graphql';
import { addStixCyberObservable, stixCyberObservableDelete } from '../../../../src/domain/stixCyberObservable';
import { ENTITY_HASHED_OBSERVABLE_ARTIFACT } from '../../../../src/schema/stixCyberObservable';

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

  const createVulnerabilities = async (prefix: string) => {
    const vulnerabilities: BasicStoreEntity[] = [];
    for (const suffix of ['V1', 'V2', 'V3']) {
      vulnerabilities.push(await addVulnerability(testContext, ADMIN_USER, { name: `${prefix} ${suffix}` }));
    }
    return vulnerabilities;
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

  const deleteVulnerabilities = async (vulnerabilities: BasicStoreEntity[]) => {
    for (const vulnerability of vulnerabilities) {
      await stixDomainObjectDelete(testContext, ADMIN_USER, vulnerability.id, ENTITY_TYPE_VULNERABILITY);
    }
  };

  const listCoveredTargetIds = async (resultId: string, context: AuthContext = testContext) => {
    const relations = await fullRelationsList<BasicStoreRelation>(context, ADMIN_USER, RELATION_HAS_COVERED, { fromId: resultId });
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
    await stixDomainObjectDelete(testContext, ADMIN_USER, report.internal_id, ENTITY_TYPE_CONTAINER_REPORT);
    await deleteAttackPatterns(attackPatterns);
  });

  it('should remove the has-covered of every entity removed from a covered report by a field patch, keeping the other ones', async () => {
    const prefix = 'sc-cleanup-field-patch';
    const attackPatterns = await createAttackPatterns(prefix);
    const report: StoreEntityReport = await addReport(testContext, ADMIN_USER, {
      name: `${prefix} report`,
      published: '2026-04-24T19:15:00.000Z',
      objects: attackPatterns.map((attackPattern) => attackPattern.standard_id),
    });
    const { securityCoverage, result } = await createCoverageCoveringAll(prefix, report.standard_id, attackPatterns);

    // The bulk "remove from container" task patches the objects field with internal ids, API clients often send standard ids
    const [firstRemoved, secondRemoved, stillInReport] = attackPatterns;
    await stixDomainObjectEditField(testContext, ADMIN_USER, report.internal_id, [
      { key: INPUT_OBJECTS, value: [firstRemoved.internal_id, secondRemoved.standard_id], operation: EditOperation.Remove },
    ]);

    expect(await listCoveredTargetIds(result.id)).toEqual(sortedIds([stillInReport]));

    await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.standard_id);
    await stixDomainObjectDelete(testContext, ADMIN_USER, report.internal_id, ENTITY_TYPE_CONTAINER_REPORT);
    await deleteAttackPatterns(attackPatterns);
  });

  it('should remove the has-covered of an artifact removed from a covered report by a field patch', async () => {
    const prefix = 'sc-cleanup-field-patch-artifact';
    const attackPattern: BasicStoreEntity = await addAttackPattern(testContext, ADMIN_USER, { name: `${prefix} AP1` });
    // Artifacts are observables, but the assessed scope keeps them among the container refs
    const artifact: BasicStoreEntity = await addStixCyberObservable(testContext, ADMIN_USER, {
      type: ENTITY_HASHED_OBSERVABLE_ARTIFACT,
      Artifact: {
        mime_type: 'text/plain',
        hashes: [{ algorithm: 'SHA-256', hash: 'b1c58c5ce6d1d6c3f8c1e2e5a6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3' }],
        x_opencti_description: `${prefix} artifact`,
      },
    });
    const report: StoreEntityReport = await addReport(testContext, ADMIN_USER, {
      name: `${prefix} report`,
      published: '2026-04-24T19:15:00.000Z',
      objects: [attackPattern.standard_id, artifact.standard_id],
    });
    const { securityCoverage, result } = await createCoverageCoveringAll(prefix, report.standard_id, [attackPattern, artifact]);
    expect(await listCoveredTargetIds(result.id)).toEqual(sortedIds([attackPattern, artifact]));

    await stixDomainObjectEditField(testContext, ADMIN_USER, report.internal_id, [
      { key: INPUT_OBJECTS, value: [artifact.internal_id], operation: EditOperation.Remove },
    ]);

    expect(await listCoveredTargetIds(result.id)).toEqual(sortedIds([attackPattern]));

    await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.standard_id);
    await stixDomainObjectDelete(testContext, ADMIN_USER, report.internal_id, ENTITY_TYPE_CONTAINER_REPORT);
    await stixCyberObservableDelete(testContext, ADMIN_USER, artifact.id);
    await deleteAttackPatterns([attackPattern]);
  });

  it('should remove the has-covered of a vulnerability untargeted by a covered campaign, keeping the other ones', async () => {
    const prefix = 'sc-cleanup-campaign-targets';
    const vulnerabilities = await createVulnerabilities(prefix);
    const campaign: BasicStoreEntity = await addCampaign(testContext, ADMIN_USER, { name: `${prefix} campaign` });
    const targetsRelations = [];
    for (const vulnerability of vulnerabilities) {
      targetsRelations.push(await addStixCoreRelationship(testContext, ADMIN_USER, {
        fromId: campaign.standard_id,
        toId: vulnerability.standard_id,
        relationship_type: RELATION_TARGETS,
      }));
    }
    const { securityCoverage, result } = await createCoverageCoveringAll(prefix, campaign.standard_id, vulnerabilities);
    expect(await listCoveredTargetIds(result.id)).toEqual(sortedIds(vulnerabilities));

    const [removed, ...stillTargeted] = vulnerabilities;
    await stixCoreRelationshipDelete(testContext, ADMIN_USER, targetsRelations[0].id);

    expect(await listCoveredTargetIds(result.id)).toEqual(sortedIds(stillTargeted));
    expect(await storeLoadById(testContext, ADMIN_USER, removed.id, ENTITY_TYPE_VULNERABILITY)).toBeDefined();

    await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.standard_id);
    await stixDomainObjectDelete(testContext, ADMIN_USER, campaign.id, ENTITY_TYPE_CAMPAIGN);
    await deleteVulnerabilities(vulnerabilities);
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

  it('should remove the has-covered of a vulnerability untargeted by a covered intrusion set, keeping the other ones', async () => {
    const prefix = 'sc-cleanup-intrusion-set-targets';
    const vulnerabilities = await createVulnerabilities(prefix);
    const intrusionSet: BasicStoreEntity = await addIntrusionSet(testContext, ADMIN_USER, { name: `${prefix} intrusion set` });
    const targetsRelations = [];
    for (const vulnerability of vulnerabilities) {
      targetsRelations.push(await addStixCoreRelationship(testContext, ADMIN_USER, {
        fromId: intrusionSet.standard_id,
        toId: vulnerability.standard_id,
        relationship_type: RELATION_TARGETS,
      }));
    }
    const { securityCoverage, result } = await createCoverageCoveringAll(prefix, intrusionSet.standard_id, vulnerabilities);
    expect(await listCoveredTargetIds(result.id)).toEqual(sortedIds(vulnerabilities));

    const [removed, ...stillTargeted] = vulnerabilities;
    await stixCoreRelationshipDelete(testContext, ADMIN_USER, targetsRelations[0].id);

    expect(await listCoveredTargetIds(result.id)).toEqual(sortedIds(stillTargeted));
    expect(await storeLoadById(testContext, ADMIN_USER, removed.id, ENTITY_TYPE_VULNERABILITY)).toBeDefined();

    await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.standard_id);
    await stixDomainObjectDelete(testContext, ADMIN_USER, intrusionSet.id, ENTITY_TYPE_INTRUSION_SET);
    await deleteVulnerabilities(vulnerabilities);
  });

  it('should remove the has-covered of an entity unlinked by from and to, and stay unchanged when the delete is repeated', async () => {
    const prefix = 'sc-cleanup-from-to';
    const attackPatterns = await createAttackPatterns(prefix);
    const intrusionSet: BasicStoreEntity = await addIntrusionSet(testContext, ADMIN_USER, { name: `${prefix} intrusion set` });
    for (const attackPattern of attackPatterns) {
      await addStixCoreRelationship(testContext, ADMIN_USER, {
        fromId: intrusionSet.standard_id,
        toId: attackPattern.standard_id,
        relationship_type: RELATION_USES,
      });
    }
    const { securityCoverage, result } = await createCoverageCoveringAll(prefix, intrusionSet.standard_id, attackPatterns);

    const [removed, ...stillUsed] = attackPatterns;
    // The GraphQL mutation passes standard ids
    await stixCoreRelationshipDeleteByFromAndTo(testContext, ADMIN_USER, intrusionSet.standard_id, removed.standard_id, RELATION_USES);
    expect(await listCoveredTargetIds(result.id)).toEqual(sortedIds(stillUsed));

    await stixCoreRelationshipDeleteByFromAndTo(testContext, ADMIN_USER, intrusionSet.standard_id, removed.standard_id, RELATION_USES);
    expect(await listCoveredTargetIds(result.id)).toEqual(sortedIds(stillUsed));

    await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.standard_id);
    await stixDomainObjectDelete(testContext, ADMIN_USER, intrusionSet.id, ENTITY_TYPE_INTRUSION_SET);
    await deleteAttackPatterns(attackPatterns);
  });

  it('should keep the has-covered of an entity still used through another uses relationship', async () => {
    const prefix = 'sc-cleanup-double-uses';
    const attackPatterns = await createAttackPatterns(prefix);
    const intrusionSet: BasicStoreEntity = await addIntrusionSet(testContext, ADMIN_USER, { name: `${prefix} intrusion set` });
    const [twiceUsed] = attackPatterns;
    // Same pair, periods far enough apart to stay two distinct relationships
    const firstUse = await addStixCoreRelationship(testContext, ADMIN_USER, {
      fromId: intrusionSet.standard_id,
      toId: twiceUsed.standard_id,
      relationship_type: RELATION_USES,
      start_time: '2020-01-01T00:00:00.000Z',
      stop_time: '2020-12-31T00:00:00.000Z',
    });
    await addStixCoreRelationship(testContext, ADMIN_USER, {
      fromId: intrusionSet.standard_id,
      toId: twiceUsed.standard_id,
      relationship_type: RELATION_USES,
      start_time: '2023-01-01T00:00:00.000Z',
      stop_time: '2023-12-31T00:00:00.000Z',
    });
    const { securityCoverage, result } = await createCoverageCoveringAll(prefix, intrusionSet.standard_id, [twiceUsed]);

    await stixCoreRelationshipDelete(testContext, ADMIN_USER, firstUse.id);

    expect(await listCoveredTargetIds(result.id)).toEqual(sortedIds([twiceUsed]));

    await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.standard_id);
    await stixDomainObjectDelete(testContext, ADMIN_USER, intrusionSet.id, ENTITY_TYPE_INTRUSION_SET);
    await deleteAttackPatterns(attackPatterns);
  });

  it('should keep every has-covered when removing an entity that was never in the covered report', async () => {
    const prefix = 'sc-cleanup-never-in-report';
    const attackPatterns = await createAttackPatterns(prefix);
    const [notInReport, ...inReport] = attackPatterns;
    const report: StoreEntityReport = await addReport(testContext, ADMIN_USER, {
      name: `${prefix} report`,
      published: '2026-04-24T19:15:00.000Z',
      objects: inReport.map((attackPattern) => attackPattern.standard_id),
    });
    const { securityCoverage, result } = await createCoverageCoveringAll(prefix, report.standard_id, inReport);

    await stixDomainObjectDeleteRelation(testContext, ADMIN_USER, report.internal_id, notInReport.id, RELATION_OBJECT);

    expect(await listCoveredTargetIds(result.id)).toEqual(sortedIds(inReport));

    await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.standard_id);
    await stixDomainObjectDelete(testContext, ADMIN_USER, report.internal_id, ENTITY_TYPE_CONTAINER_REPORT);
    await deleteAttackPatterns(attackPatterns);
  });

  it('should remove the has-covered in the draft only when the entity is removed from the covered report in a draft', async () => {
    const prefix = 'sc-cleanup-draft';
    const attackPatterns = await createAttackPatterns(prefix);
    const report: StoreEntityReport = await addReport(testContext, ADMIN_USER, {
      name: `${prefix} report`,
      published: '2026-04-24T19:15:00.000Z',
      objects: attackPatterns.map((attackPattern) => attackPattern.standard_id),
    });
    const { securityCoverage, result } = await createCoverageCoveringAll(prefix, report.standard_id, attackPatterns);
    const draft = await addDraftWorkspace(testContext, ADMIN_USER, { name: `${prefix} draft` });
    const draftContext: AuthContext = { ...testContext, draft_context: draft.id };

    const [removed, ...stillInReport] = attackPatterns;
    await stixDomainObjectDeleteRelation(draftContext, ADMIN_USER, report.internal_id, removed.id, RELATION_OBJECT);

    // The cleanup lands in the draft, the live has-covered are untouched
    expect(await listCoveredTargetIds(result.id, draftContext)).toEqual(sortedIds(stillInReport));
    expect(await listCoveredTargetIds(result.id)).toEqual(sortedIds(attackPatterns));

    // Discarding the draft drops the removal and its cleanup together
    await deleteElementById(testContext, ADMIN_USER, draft.id, ENTITY_TYPE_DRAFT_WORKSPACE);
    expect(await listCoveredTargetIds(result.id)).toEqual(sortedIds(attackPatterns));

    await securityCoverageDelete(testContext, ADMIN_USER, securityCoverage.standard_id);
    await stixDomainObjectDelete(testContext, ADMIN_USER, report.internal_id, ENTITY_TYPE_CONTAINER_REPORT);
    await deleteAttackPatterns(attackPatterns);
  });
});

describe('Single-valued ref relationships through the ref relation API', () => {
  // pycti update_created_by removes the current author through this API before adding the new one
  it('should accept adding then removing the author of an entity', async () => {
    const author = await addOrganization(testContext, ADMIN_USER, { name: 'sc-cleanup created-by author' });
    const attackPattern = await addAttackPattern(testContext, ADMIN_USER, { name: 'sc-cleanup created-by attack pattern' });

    await stixDomainObjectAddRelation(testContext, ADMIN_USER, attackPattern.id, { toId: author.id, relationship_type: RELATION_CREATED_BY });
    const withAuthor = await storeLoadByIdWithRefs(testContext, ADMIN_USER, attackPattern.id) as Record<string, any>;
    expect(withAuthor.createdBy?.internal_id).toEqual(author.internal_id);

    await expect(stixDomainObjectDeleteRelation(testContext, ADMIN_USER, attackPattern.id, author.id, RELATION_CREATED_BY)).resolves.toBeDefined();

    await stixDomainObjectDelete(testContext, ADMIN_USER, attackPattern.id, ENTITY_TYPE_ATTACK_PATTERN);
    await stixDomainObjectDelete(testContext, ADMIN_USER, author.id, ENTITY_TYPE_IDENTITY_ORGANIZATION);
  });
});
