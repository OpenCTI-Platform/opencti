import { v4 as uuidv4 } from 'uuid';
import { type EntityOptions, fullRelationsList, loadEntityThroughRelationsPaginated, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../types/user';
import { type BasicStoreEntitySecurityCoverage, ENTITY_TYPE_SECURITY_COVERAGE, INPUT_COVERED, RELATION_COVERED, type StoreEntitySecurityCoverage } from './securityCoverage-types';
import { notify } from '../../database/redis';
import { BUS_TOPICS, logApp } from '../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { createEntity, deleteElementById, storeLoadByIdsWithRefs, storeLoadByIdWithRefs } from '../../database/middleware';
import { type SecurityCoverageAddInput } from '../../generated/graphql';
import type { BasicStoreEntity, StoreObject, StoreRelation } from '../../types/store';
import { convertStoreToStix_2_1 } from '../../database/stix-2-1-converter';
import { STIX_SPEC_VERSION } from '../../database/stix';
import { RELATION_TARGETS, RELATION_USES } from '../../schema/stixCoreRelationship';
import { stixRefsExtractor } from '../../schema/stixEmbeddedRelationship';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_VULNERABILITY,
} from '../../schema/stixDomainObject';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../case/case-incident/case-incident-types';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../grouping/grouping-types';
import { deleteSecurityCoverageResultsByResultOf } from './securityCoverageResult/securityCoverageResult-domain';
import { ENTITY_TYPE_SECURITY_COVERAGE_RESULT, INPUT_RESULT_OF, type BasicStoreEntitySecurityCoverageResult } from './securityCoverageResult/securityCoverageResult-types';
import { loadThroughDenormalized } from '../../resolvers/stix';

export const COVERED_ENTITIES_TYPE = [
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_CONTAINER_GROUPING,
  ENTITY_TYPE_CONTAINER_CASE_INCIDENT,
];

// region CRUD
export const findSecurityCoverageById = async (
  context: AuthContext,
  user: AuthUser,
  SecurityCoverageId: string,
): Promise<BasicStoreEntitySecurityCoverage> => {
  const store = storeLoadById<BasicStoreEntitySecurityCoverage>(
    context,
    user,
    SecurityCoverageId,
    ENTITY_TYPE_SECURITY_COVERAGE,
  );
  return notify(
    BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC,
    store,
    user,
  );
};

export const pageSecurityCoverageConnections = (context: AuthContext, user: AuthUser, args: EntityOptions<BasicStoreEntitySecurityCoverage>) => {
  return pageEntitiesConnection<BasicStoreEntitySecurityCoverage>(context, user, [ENTITY_TYPE_SECURITY_COVERAGE], args);
};

export const findSecurityCoverageByCoveredId = async (context: AuthContext, user: AuthUser, coveredId: string) => {
  return loadEntityThroughRelationsPaginated<BasicStoreEntitySecurityCoverage>(context, user, coveredId, RELATION_COVERED, ABSTRACT_STIX_DOMAIN_OBJECT, true);
};

export const addSecurityCoverage = async (
  context: AuthContext,
  user: AuthUser,
  securityCoverageInput: SecurityCoverageAddInput,
): Promise<BasicStoreEntitySecurityCoverage> => {
  const {
    coverage_information,
    coverage_last_result,
    coverage_valid_from,
    coverage_valid_to,
    external_uri,
    ...onlySecurityCoverageInput
  } = securityCoverageInput;
  const createdSecurityCoverage: BasicStoreEntitySecurityCoverage = await createEntity(
    context,
    user,
    onlySecurityCoverageInput,
    ENTITY_TYPE_SECURITY_COVERAGE,
  );

  if (external_uri || (coverage_information ?? []).length > 0) {
    const {
      confidence,
      created,
      createdBy,
      fileMarkings,
      filesMarkings,
      modified,
      objectLabel,
      objectMarking,
      x_opencti_modified_at,
    } = onlySecurityCoverageInput;
    const securityCoverageResultInput = {
      name: `Result of ${createdSecurityCoverage.name}`,
      [INPUT_RESULT_OF]: createdSecurityCoverage.id,
      coverage_information,
      coverage_last_result,
      coverage_valid_from,
      coverage_valid_to,
      external_uri,
      confidence,
      created,
      createdBy,
      fileMarkings,
      filesMarkings,
      modified,
      objectLabel,
      objectMarking,
      x_opencti_modified_at,
    };
    const result: BasicStoreEntitySecurityCoverageResult = await createEntity(
      context,
      user,
      securityCoverageResultInput,
      ENTITY_TYPE_SECURITY_COVERAGE_RESULT,
    );
    // Manually add it here to be able to resolve dynamyc attributes
    createdSecurityCoverage['result-of'] = [result.id];
    logApp.info(`[SECURITY-COVERAGE-RESULT][${createdSecurityCoverage.id}] SCR created: ${result.standard_id}`);
  }

  return notify(
    BUS_TOPICS[ENTITY_TYPE_SECURITY_COVERAGE].EDIT_TOPIC,
    createdSecurityCoverage,
    user,
  );
};

export const securityCoverageStixBundle = async (context: AuthContext, user: AuthUser, SecurityCoverageId: string) => {
  const objects = [];
  const SecurityCoverage = await storeLoadByIdWithRefs(context, user, SecurityCoverageId) as StoreEntitySecurityCoverage;
  const stixSecurityCoverage = convertStoreToStix_2_1(SecurityCoverage);
  objects.push(stixSecurityCoverage);
  const objectCovered = SecurityCoverage[INPUT_COVERED] as BasicStoreEntity;
  const assessment = await storeLoadByIdWithRefs(context, user, objectCovered.id) as StoreObject;
  const stixAssessment = convertStoreToStix_2_1(assessment);
  objects.push(stixAssessment);
  const stixAssessmentRefs = stixRefsExtractor(stixAssessment);
  const refElements = await storeLoadByIdsWithRefs(context, user, stixAssessmentRefs);
  for (const element of refElements) {
    const refElement = element;
    const stixRefElement = convertStoreToStix_2_1(refElement);
    objects.push(stixRefElement);
  }
  const targetIds = new Set<string>();
  const relationsCallback = async (relationships: StoreRelation[]) => {
    const relations = await storeLoadByIdsWithRefs<StoreRelation>(context, user, relationships.map((r: StoreRelation) => r.id));
    for (let index = 0; index < relations.length; index += 1) {
      const relation = relations[index];
      const stixRelation = convertStoreToStix_2_1(relation);
      objects.push(stixRelation);
      targetIds.add(relation.toId);
    }
  };
  await fullRelationsList(context, user, [RELATION_TARGETS, RELATION_USES], {
    fromId: objectCovered.id,
    toTypes: [ENTITY_TYPE_VULNERABILITY, ENTITY_TYPE_ATTACK_PATTERN],
    callback: relationsCallback,
  });
  if (targetIds.size > 0) {
    const targets = await storeLoadByIdsWithRefs(context, user, Array.from(targetIds));
    for (let index = 0; index < targets.length; index += 1) {
      const target = targets[index];
      const stixTarget = convertStoreToStix_2_1(target);
      objects.push(stixTarget);
    }
  }
  const StixBundle = { id: uuidv4(), spec_version: STIX_SPEC_VERSION, type: 'bundle', objects };
  return JSON.stringify(StixBundle);
};

export const objectCovered = async <T extends BasicStoreEntity>(context: AuthContext, user: AuthUser, SecurityCoverageId: string) => {
  return loadEntityThroughRelationsPaginated<T>(context, user, SecurityCoverageId, RELATION_COVERED, COVERED_ENTITIES_TYPE, false);
};

export const securityCoverageDelete = async (context: AuthContext, user: AuthUser, securityCoverageId: string) => {
  const deletedResults = await deleteSecurityCoverageResultsByResultOf(context, user, securityCoverageId);
  logApp.info(`[SECURITY-COVERAGE-RESULT][${securityCoverageId}] SCR deleted: ${deletedResults}`);
  await deleteElementById(context, user, securityCoverageId, ENTITY_TYPE_SECURITY_COVERAGE);
  await notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].DELETE_TOPIC, securityCoverageId, user);
  return securityCoverageId;
};
// endregion

export const getSecurityCoverageResultProperty = async (
  context: AuthContext,
  user: AuthUser,
  securityCoverage: BasicStoreEntitySecurityCoverage,
  property: keyof BasicStoreEntitySecurityCoverageResult,
) => {
  const results = await loadThroughDenormalized(context, user, securityCoverage, INPUT_RESULT_OF);

  if (!results[0]) {
    return undefined;
  }

  return results[0][property];
};
