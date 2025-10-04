import { v4 as uuidv4 } from 'uuid';
import { type EntityOptions, fullRelationsList, loadEntityThroughRelationsPaginated, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader'; import type { AuthContext, AuthUser } from '../../types/user';
import { type BasicStoreEntitySecurityCoverage, ENTITY_TYPE_SECURITY_COVERAGE, INPUT_COVERED, RELATION_COVERED } from './securityCoverage-types';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { createEntity, deleteElementById, storeLoadByIdsWithRefs, storeLoadByIdWithRefs } from '../../database/middleware';
import type { SecurityCoverageAddInput } from '../../generated/graphql';
import type { BasicStoreEntity, StoreRelation } from '../../types/store';
import { ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_THREAT_ACTOR_GROUP } from '../../schema/stixDomainObject';
import { convertStoreToStix } from '../../database/stix-2-1-converter';
import { STIX_SPEC_VERSION } from '../../database/stix';
import { STIX_CORE_RELATIONSHIPS } from '../../schema/stixCoreRelationship';
import { stixRefsExtractor } from '../../schema/stixEmbeddedRelationship';

// region CRUD
export const findById = (context: AuthContext, user: AuthUser, SecurityCoverageId: string) => {
  return storeLoadById<BasicStoreEntitySecurityCoverage>(context, user, SecurityCoverageId, ENTITY_TYPE_SECURITY_COVERAGE);
};

export const findAll = (context: AuthContext, user: AuthUser, args: EntityOptions<BasicStoreEntitySecurityCoverage>) => {
  return pageEntitiesConnection<BasicStoreEntitySecurityCoverage>(context, user, [ENTITY_TYPE_SECURITY_COVERAGE], args);
};

export const addSecurityCoverage = async (context: AuthContext, user: AuthUser, securityCoverageInput: SecurityCoverageAddInput) => {
  const created = await createEntity(context, user, securityCoverageInput, ENTITY_TYPE_SECURITY_COVERAGE);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const securityCoverageStixBundle = async (context: AuthContext, user: AuthUser, SecurityCoverageId: string) => {
  const objects = [];
  const SecurityCoverage = await storeLoadByIdWithRefs(context, user, SecurityCoverageId);
  const stixSecurityCoverage = convertStoreToStix(SecurityCoverage);
  objects.push(stixSecurityCoverage);
  const objectCovered = SecurityCoverage[INPUT_COVERED] as unknown as BasicStoreEntity;
  const assessment = await storeLoadByIdWithRefs(context, user, objectCovered.id);
  const stixAssessment = convertStoreToStix(assessment);
  objects.push(stixAssessment);
  const stixAssessmentRefs = stixRefsExtractor(stixAssessment);
  const refElements = await storeLoadByIdsWithRefs(context, user, stixAssessmentRefs);
  for (let index = 0; index < refElements.length; index += 1) {
    const refElement = refElements[index];
    const stixRefElement = convertStoreToStix(refElement);
    objects.push(stixRefElement);
  }
  const targetIds = new Set();
  const relationsCallback = async (relationships: StoreRelation[]) => {
    const relations = await storeLoadByIdsWithRefs(context, user, relationships.map((r: StoreRelation) => r.id));
    for (let index = 0; index < relations.length; index += 1) {
      const relation = relations[index];
      const stixRelation = convertStoreToStix(relation);
      objects.push(stixRelation);
      targetIds.add(relation.toId);
    }
  };
  await fullRelationsList(context, user, STIX_CORE_RELATIONSHIPS, { fromId: objectCovered.id, callback: relationsCallback });
  if (targetIds.size > 0) {
    const targets = await storeLoadByIdsWithRefs(context, user, Array.from(targetIds));
    for (let index = 0; index < targets.length; index += 1) {
      const target = targets[index];
      const stixTarget = convertStoreToStix(target);
      objects.push(stixTarget);
    }
  }
  const StixBundle = { id: uuidv4(), spec_version: STIX_SPEC_VERSION, type: 'bundle', objects };
  return JSON.stringify(StixBundle);
};

export const objectCovered = async <T extends BasicStoreEntity>(context: AuthContext, user: AuthUser, SecurityCoverageId: string) => {
  const entityTypes = [ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_THREAT_ACTOR_GROUP];
  return loadEntityThroughRelationsPaginated<T>(context, user, SecurityCoverageId, RELATION_COVERED, entityTypes, false);
};

export const securityCoverageDelete = async (context: AuthContext, user: AuthUser, SecurityCoverageId: string) => {
  await deleteElementById(context, user, SecurityCoverageId, ENTITY_TYPE_SECURITY_COVERAGE);
  await notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].DELETE_TOPIC, SecurityCoverageId, user);
  return SecurityCoverageId;
};
// endregion
