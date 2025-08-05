import { v4 as uuidv4 } from 'uuid';
import { type EntityOptions, listAllRelations, listEntitiesPaginated, loadEntityThroughRelationsPaginated, storeLoadById } from '../../database/middleware-loader'; import type { AuthContext, AuthUser } from '../../types/user';
import { type BasicStoreEntitySecurityAssessment, ENTITY_TYPE_SECURITY_ASSESSMENT, INPUT_ASSESS, RELATION_ASSESS } from './securityAssessment-types';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { createEntity, deleteElementById, storeLoadByIdsWithRefs, storeLoadByIdWithRefs } from '../../database/middleware';
import type { SecurityAssessmentAddInput } from '../../generated/graphql';
import type { BasicStoreCommon, BasicStoreEntity, StoreRelation } from '../../types/store';
import { ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_THREAT_ACTOR_GROUP } from '../../schema/stixDomainObject';
import { convertStoreToStix } from '../../database/stix-2-1-converter';
import { STIX_SPEC_VERSION } from '../../database/stix';
import { STIX_CORE_RELATIONSHIPS } from '../../schema/stixCoreRelationship';
import { stixRefsExtractor } from '../../schema/stixEmbeddedRelationship';

// region CRUD
export const findById = (context: AuthContext, user: AuthUser, securityAssessmentId: string) => {
  return storeLoadById<BasicStoreEntitySecurityAssessment>(context, user, securityAssessmentId, ENTITY_TYPE_SECURITY_ASSESSMENT);
};

export const findAll = (context: AuthContext, user: AuthUser, args: EntityOptions<BasicStoreEntitySecurityAssessment>) => {
  return listEntitiesPaginated<BasicStoreEntitySecurityAssessment>(context, user, [ENTITY_TYPE_SECURITY_ASSESSMENT], args);
};

export const addSecurityAssessment = async (context: AuthContext, user: AuthUser, securityAssessment: SecurityAssessmentAddInput) => {
  const created = await createEntity(context, user, securityAssessment, ENTITY_TYPE_SECURITY_ASSESSMENT);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const securityAssessmentStixBundle = async (context: AuthContext, user: AuthUser, securityAssessmentId: string) => {
  const objects = [];
  const securityAssessment = await storeLoadByIdWithRefs(context, user, securityAssessmentId);
  const stixSecurityAssessment = convertStoreToStix(securityAssessment);
  objects.push(stixSecurityAssessment);
  const objectAsses = securityAssessment[INPUT_ASSESS] as unknown as BasicStoreEntity;
  const assessment = await storeLoadByIdWithRefs(context, user, objectAsses.id);
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
  await listAllRelations(context, user, STIX_CORE_RELATIONSHIPS, { fromId: objectAsses.id, callback: relationsCallback });
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

export const objectAssess = async <T extends BasicStoreCommon>(context: AuthContext, user: AuthUser, securityAssessmentId: string) => {
  const entityTypes = [ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_THREAT_ACTOR_GROUP];
  return loadEntityThroughRelationsPaginated<T>(context, user, securityAssessmentId, RELATION_ASSESS, entityTypes, false);
};

export const securityAssessmentDelete = async (context: AuthContext, user: AuthUser, securityAssessmentId: string) => {
  await deleteElementById(context, user, securityAssessmentId, ENTITY_TYPE_SECURITY_ASSESSMENT);
  await notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].DELETE_TOPIC, securityAssessmentId, user);
  return securityAssessmentId;
};
// endregion
