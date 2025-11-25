import { v4 as uuidv4 } from 'uuid';
import { type EntityOptions, fullRelationsList, loadEntityThroughRelationsPaginated, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader'; import type { AuthContext, AuthUser } from '../../types/user';
import { type BasicStoreEntitySecurityCoverage, ENTITY_TYPE_SECURITY_COVERAGE, INPUT_COVERED, RELATION_COVERED } from './securityCoverage-types';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { createEntity, deleteElementById, storeLoadByIdsWithRefs, storeLoadByIdWithRefs } from '../../database/middleware';
import type { SecurityCoverageAddInput } from '../../generated/graphql';
import type { BasicStoreEntity, StoreRelation } from '../../types/store';
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
  ENTITY_TYPE_VULNERABILITY
} from '../../schema/stixDomainObject';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../case/case-incident/case-incident-types';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../grouping/grouping-types';

export const COVERED_ENTITIES_TYPE = [
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_CONTAINER_GROUPING,
  ENTITY_TYPE_CONTAINER_CASE_INCIDENT,
];

// region CRUD
export const findSecurityCoverageById = (context: AuthContext, user: AuthUser, SecurityCoverageId: string) => {
  return storeLoadById<BasicStoreEntitySecurityCoverage>(context, user, SecurityCoverageId, ENTITY_TYPE_SECURITY_COVERAGE);
};

export const pageSecurityCoverageConnections = (context: AuthContext, user: AuthUser, args: EntityOptions<BasicStoreEntitySecurityCoverage>) => {
  return pageEntitiesConnection<BasicStoreEntitySecurityCoverage>(context, user, [ENTITY_TYPE_SECURITY_COVERAGE], args);
};

export const findSecurityCoverageByCoveredId = async (context: AuthContext, user: AuthUser, coveredId: string) => {
  return loadEntityThroughRelationsPaginated<BasicStoreEntitySecurityCoverage>(context, user, coveredId, RELATION_COVERED, ABSTRACT_STIX_DOMAIN_OBJECT, true);
};

export const addSecurityCoverage = async (context: AuthContext, user: AuthUser, securityCoverageInput: SecurityCoverageAddInput) => {
  const created = await createEntity(context, user, securityCoverageInput, ENTITY_TYPE_SECURITY_COVERAGE);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const securityCoverageStixBundle = async (context: AuthContext, user: AuthUser, SecurityCoverageId: string) => {
  const objects = [];
  const SecurityCoverage = await storeLoadByIdWithRefs(context, user, SecurityCoverageId);
  const stixSecurityCoverage = convertStoreToStix_2_1(SecurityCoverage);
  objects.push(stixSecurityCoverage);
  const objectCovered = SecurityCoverage[INPUT_COVERED] as unknown as BasicStoreEntity;
  const assessment = await storeLoadByIdWithRefs(context, user, objectCovered.id);
  const stixAssessment = convertStoreToStix_2_1(assessment);
  objects.push(stixAssessment);
  const stixAssessmentRefs = stixRefsExtractor(stixAssessment);
  const refElements = await storeLoadByIdsWithRefs(context, user, stixAssessmentRefs);
  for (let index = 0; index < refElements.length; index += 1) {
    const refElement = refElements[index];
    const stixRefElement = convertStoreToStix_2_1(refElement);
    objects.push(stixRefElement);
  }
  const targetIds = new Set();
  const relationsCallback = async (relationships: StoreRelation[]) => {
    const relations = await storeLoadByIdsWithRefs(context, user, relationships.map((r: StoreRelation) => r.id));
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
    callback: relationsCallback
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

export const securityCoverageDelete = async (context: AuthContext, user: AuthUser, SecurityCoverageId: string) => {
  await deleteElementById(context, user, SecurityCoverageId, ENTITY_TYPE_SECURITY_COVERAGE);
  await notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].DELETE_TOPIC, SecurityCoverageId, user);
  return SecurityCoverageId;
};
// endregion
