import { v4 as uuidv4 } from 'uuid';
import {
  type EntityOptions,
  fullRelationsList,
  internalFindByIds,
  internalFindByIdsMapped,
  loadEntityThroughRelationsPaginated,
  pageEntitiesConnection,
  storeLoadById,
} from '../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../types/user';
import {
  type BasicStoreEntitySecurityCoverage,
  type CoveredEntity,
  ENTITY_TYPE_SECURITY_COVERAGE,
  INPUT_COVERED,
  RELATION_COVERED,
  type StoreEntitySecurityCoverage,
} from './securityCoverage-types';
import { notify } from '../../database/redis';
import { BUS_TOPICS, logApp } from '../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { createEntity, deleteElementById, distributionRelations, storeLoadByIdsWithRefs, storeLoadByIdWithRefs } from '../../database/middleware';
import { type SecurityCoverageAddInput } from '../../generated/graphql';
import type { BasicStoreEntity, BasicStoreObject, BasicStoreRelation, StoreObject, StoreRelation } from '../../types/store';
import { convertStoreToStix_2_1 } from '../../database/stix-2-1-converter';
import { STIX_SPEC_VERSION } from '../../database/stix';
import { RELATION_HAS_COVERED, RELATION_TARGETS, RELATION_USES } from '../../schema/stixCoreRelationship';
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
import {
  ENTITY_TYPE_SECURITY_COVERAGE_RESULT,
  INPUT_RESULT_OF,
  RELATION_RESULT_OF,
  type BasicStoreEntitySecurityCoverageResult,
  type CoverageInformation,
  type StoreEntitySecurityCoverageResult,
} from './securityCoverageResult/securityCoverageResult-types';
import { loadThroughDenormalized } from '../../resolvers/stix';
import { stixCoreRelationshipsPaginated } from '../../domain/stixCoreObject';
import { getAverageCoverageInformation, getMostRecentLastCoverageResult, internalCreateSecurityCoverageResult } from './securityCoverageResult/securityCoverageResult-utils';
import { splitSecurityCoverageInput } from './securityCoverage-utils';
import { emptyPaginationResult } from '../../database/utils';
import { createHasCoveredRelTask } from './securityCoverageResult/securityCoverageResult-domain';

export const COVERED_ENTITIES_TYPE = [
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_CONTAINER_GROUPING,
  ENTITY_TYPE_CONTAINER_CASE_INCIDENT,
];

// region CRUD
export const findById = async (
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

export const findSecurityCoveragePaginated = (context: AuthContext, user: AuthUser, args: EntityOptions<BasicStoreEntitySecurityCoverage>) => {
  return pageEntitiesConnection<BasicStoreEntitySecurityCoverage>(context, user, [ENTITY_TYPE_SECURITY_COVERAGE], args);
};

export const findSecurityCoverageByCoveredId = async (context: AuthContext, user: AuthUser, coveredId: string) => {
  return loadEntityThroughRelationsPaginated<BasicStoreEntitySecurityCoverage>(context, user, coveredId, RELATION_COVERED, ABSTRACT_STIX_DOMAIN_OBJECT, true);
};

export const addSecurityCoverage = async (
  context: AuthContext,
  user: AuthUser,
  input: SecurityCoverageAddInput,
): Promise<BasicStoreEntitySecurityCoverage> => {
  const {
    securityCoverageInput,
    securityCoverageResultInput,
    add_related_entities,
    shouldCreateResult,
  } = splitSecurityCoverageInput(input);

  // 1. Create the SecurityCoverage entity.
  const createdSecurityCoverage: BasicStoreEntitySecurityCoverage = await createEntity(
    context,
    user,
    securityCoverageInput,
    ENTITY_TYPE_SECURITY_COVERAGE,
  );

  // 2. Create an associated SecurityCoverageResult if we also
  // have data for it (when receiving bundles from OpenAEV) or manual creation.
  let result: BasicStoreEntitySecurityCoverageResult | undefined;
  if (shouldCreateResult) {
    result = await internalCreateSecurityCoverageResult(context, user, {
      ...securityCoverageResultInput,
      // Add extra attributes based on created SecurityCoverage
      [INPUT_RESULT_OF]: createdSecurityCoverage.id,
      name: `${securityCoverageResultInput.name ?? ''} Result of ${createdSecurityCoverage.name}`.trim(),
    });
    // Manually add the ref here to be able to resolve dynamic attributes in GraphQL response
    createdSecurityCoverage[RELATION_RESULT_OF] = [result.id];
  }

  // 3. In case of manual creation, need to create associated has-covered relationships.
  if (add_related_entities) {
    if (!result) {
      // We should not arrive here. If asked to add related entities, a SecurityCoverageResult
      // should have been created, otherwise there was an error.
      logApp.error(
        `[SECURITY-COVERAGE] Error while trying to add related entities to the created SecurityCoverage ${createdSecurityCoverage.id}, no SecurityCoverageResult was created.`,
        { securityCoverageResultInput, shouldCreateResult },
      );
    } else {
      await createHasCoveredRelTask(context, user, result.id);
    }
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
  const securityCoverage = await findById(context, user, securityCoverageId);
  const deletedResults = await deleteSecurityCoverageResultsByResultOf(context, user, securityCoverage);
  logApp.info(`[SECURITY-COVERAGE-RESULT][${securityCoverageId}] SCR deleted: ${deletedResults}`);
  await deleteElementById(context, user, securityCoverageId, ENTITY_TYPE_SECURITY_COVERAGE);
  await notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].DELETE_TOPIC, securityCoverageId, user);
  return securityCoverageId;
};
// endregion

/**
 * Delete all security coverage results for a security coverage.
 *
 * @param context
 * @param user User making the request.
 * @param resultOfId ID of the security coverage.
 * @returns List of IDs deleted results.
 */
export const deleteSecurityCoverageResultsByResultOf = async (
  context: AuthContext,
  user: AuthUser,
  securityCoverage: BasicStoreEntitySecurityCoverage,
) => {
  const deletedIds: string[] = [];
  const results = await listSecurityCoverageResults(context, user, securityCoverage);
  for (const result of results) {
    const deleted = await deleteElementById<StoreEntitySecurityCoverageResult>(
      context,
      user,
      result.id,
      ENTITY_TYPE_SECURITY_COVERAGE_RESULT,
    );
    deletedIds.push(deleted.standard_id);
  }
  return deletedIds;
};

export const getSecurityCoverageResultIds = (securityCoverage: BasicStoreEntitySecurityCoverage): string[] => {
  return securityCoverage[RELATION_RESULT_OF] ?? [];
};

export const findCoveredEntitiesDistribution = async (
  context: AuthContext,
  user: AuthUser,
  securityCoverage: BasicStoreEntitySecurityCoverage,
  args: Record<string, unknown>,
) => {
  const resultIds = getSecurityCoverageResultIds(securityCoverage);
  if (resultIds.length === 0) {
    return [];
  }
  return distributionRelations(context, user, { ...args, fromOrToId: resultIds } as never);
};

export const findResultsRelationshipsPaginated = (
  context: AuthContext,
  user: AuthUser,
  securityCoverage: BasicStoreEntitySecurityCoverage,
  args: EntityOptions<BasicStoreRelation>,
): ReturnType<typeof stixCoreRelationshipsPaginated> => {
  const resultIds = getSecurityCoverageResultIds(securityCoverage);
  if (resultIds.length === 0) {
    return Promise.resolve(emptyPaginationResult<BasicStoreRelation>());
  }
  return stixCoreRelationshipsPaginated(context, user, resultIds, args);
};

export const listSecurityCoverageResults = (
  context: AuthContext,
  user: AuthUser,
  securityCoverage: BasicStoreEntitySecurityCoverage,
): Promise<BasicStoreEntitySecurityCoverageResult[]> => {
  return internalFindByIds(context, user, getSecurityCoverageResultIds(securityCoverage)) as Promise<BasicStoreEntitySecurityCoverageResult[]>;
};

export const loadSecurityCoverageResults = async (
  context: AuthContext,
  user: AuthUser,
  securityCoverage: BasicStoreEntitySecurityCoverage,
): Promise<BasicStoreEntitySecurityCoverageResult[]> => {
  return loadThroughDenormalized(context, user, securityCoverage, INPUT_RESULT_OF);
};

type CoveredRelation = BasicStoreRelation & { coverage_information?: CoverageInformation[] };
export const findCoveredEntities = async (
  context: AuthContext,
  user: AuthUser,
  securityCoverage: BasicStoreEntitySecurityCoverage,
  toType: string,
  args: EntityOptions<BasicStoreEntity>,
): Promise<{ count: number; entities: CoveredEntity[] }> => {
  const resultIds = getSecurityCoverageResultIds(securityCoverage);
  if (resultIds.length === 0) {
    return { count: 0, entities: [] };
  }
  const relationships = await stixCoreRelationshipsPaginated(context, user, resultIds, {
    ...args,
    relationship_type: RELATION_HAS_COVERED,
    toTypes: [toType],
  });
  const nodes: CoveredRelation[] = (relationships.edges ?? []).map((edge: { node: CoveredRelation }) => edge.node);
  const toIds = nodes.map((node) => node.toId);
  const targetsById = await internalFindByIdsMapped<BasicStoreObject>(context, user, toIds, { type: toType });
  const entities: CoveredEntity[] = nodes.map((node) => ({
    relationship_id: node.id,
    coverage_information: node.coverage_information,
    to: targetsById[node.toId] ?? null,
  }));
  return { count: relationships.pageInfo?.globalCount ?? entities.length, entities };
};

export const loadSecurityCoverageResultProperty = async (
  context: AuthContext,
  user: AuthUser,
  securityCoverage: BasicStoreEntitySecurityCoverage,
  property: keyof BasicStoreEntitySecurityCoverageResult,
) => {
  const results = await loadThroughDenormalized(context, user, securityCoverage, INPUT_RESULT_OF);
  if (results.length !== 1) return undefined;
  return results[0][property];
};

export const loadMostRecentLastCoverageResult = async (
  context: AuthContext,
  user: AuthUser,
  securityCoverage: BasicStoreEntitySecurityCoverage,
) => {
  const results: StoreEntitySecurityCoverageResult[] = await loadThroughDenormalized(
    context,
    user,
    securityCoverage,
    INPUT_RESULT_OF,
  );
  return getMostRecentLastCoverageResult(results);
};

export const loadAverageCoverageInformation = async (
  context: AuthContext,
  user: AuthUser,
  securityCoverage: BasicStoreEntitySecurityCoverage,
) => {
  const results = await loadThroughDenormalized(
    context,
    user,
    securityCoverage,
    INPUT_RESULT_OF,
  );
  return getAverageCoverageInformation(results);
};
