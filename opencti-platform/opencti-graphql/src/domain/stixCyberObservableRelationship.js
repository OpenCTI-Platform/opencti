import { propOr } from 'ramda';
import { stixCoreRelationshipCleanContext, stixCoreRelationshipEditContext } from './stixCoreRelationship';
import { batchListThroughGetFrom, createRelation, deleteElementById, storeLoadById, updateAttribute } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP } from '../schema/general';
import { FunctionalError } from '../config/errors';
import { isStixCyberObservableRelationship } from '../schema/stixCyberObservableRelationship';
import { listRelations } from '../database/middleware-loader';
import { RELATION_OBJECT } from '../schema/stixMetaRelationship';
import { ENTITY_TYPE_CONTAINER_NOTE, ENTITY_TYPE_CONTAINER_OPINION, ENTITY_TYPE_CONTAINER_REPORT } from '../schema/stixDomainObject';

export const findAll = async (user, args) => {
  return listRelations(user, propOr(ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP, 'relationship_type', args), args);
};

export const findById = (user, stixCyberObservableRelationshipId) => {
  return storeLoadById(user, stixCyberObservableRelationshipId, ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP);
};

export const batchReports = async (user, stixCyberObservableRelationshipIds) => {
  return batchListThroughGetFrom(user, stixCyberObservableRelationshipIds, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_REPORT);
};

export const batchNotes = (user, stixCyberObservableRelationshipIds) => {
  return batchListThroughGetFrom(user, stixCyberObservableRelationshipIds, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_NOTE);
};

export const batchOpinions = (user, stixCyberObservableRelationshipIds) => {
  return batchListThroughGetFrom(user, stixCyberObservableRelationshipIds, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_OPINION);
};

// region mutations
export const addStixCyberObservableRelationship = async (user, stixCyberObservableRelationship) => {
  if (!isStixCyberObservableRelationship(stixCyberObservableRelationship.relationship_type)) {
    throw FunctionalError('Only stix-cyber-observable-relationship can be created through this method.');
  }
  const created = await createRelation(user, stixCyberObservableRelationship);
  return notify(BUS_TOPICS[ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP].ADDED_TOPIC, created, user);
};

export const stixCyberObservableRelationshipDelete = async (user, stixCyberObservableRelationshipId) => {
  return deleteElementById(user, stixCyberObservableRelationshipId, ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP);
};

export const stixCyberObservableRelationshipCleanContext = (user, stixCyberObservableRelationshipId) => {
  return stixCoreRelationshipCleanContext(user, stixCyberObservableRelationshipId);
};

export const stixCyberObservableRelationshipEditContext = (user, stixCyberObservableRelationshipId, input) => {
  return stixCoreRelationshipEditContext(user, stixCyberObservableRelationshipId, input);
};

export const stixCyberObservableRelationshipEditField = async (user, relationshipId, input) => {
  const { element } = await updateAttribute(user, relationshipId, ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP, input);
  return notify(BUS_TOPICS[ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP].EDIT_TOPIC, element, user);
};
// endregion
