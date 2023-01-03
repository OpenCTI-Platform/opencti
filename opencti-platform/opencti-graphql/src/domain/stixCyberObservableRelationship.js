import { propOr } from 'ramda';
import { stixCoreRelationshipCleanContext, stixCoreRelationshipEditContext } from './stixCoreRelationship';
import { batchListThroughGetFrom, createRelation, deleteElementById, updateAttribute } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP } from '../schema/general';
import { FunctionalError } from '../config/errors';
import { isStixCyberObservableRelationship } from '../schema/stixCyberObservableRelationship';
import { listRelations, storeLoadById } from '../database/middleware-loader';
import { RELATION_OBJECT } from '../schema/stixMetaRelationship';
import { ENTITY_TYPE_CONTAINER_NOTE, ENTITY_TYPE_CONTAINER_OPINION, ENTITY_TYPE_CONTAINER_REPORT } from '../schema/stixDomainObject';

export const findAll = async (context, user, args) => {
  return listRelations(context, user, propOr(ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP, 'relationship_type', args), args);
};

export const findById = (context, user, stixCyberObservableRelationshipId) => {
  return storeLoadById(context, user, stixCyberObservableRelationshipId, ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP);
};

export const batchReports = async (context, user, stixCyberObservableRelationshipIds) => {
  return batchListThroughGetFrom(context, user, stixCyberObservableRelationshipIds, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_REPORT);
};

export const batchNotes = (context, user, stixCyberObservableRelationshipIds) => {
  return batchListThroughGetFrom(context, user, stixCyberObservableRelationshipIds, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_NOTE);
};

export const batchOpinions = (context, user, stixCyberObservableRelationshipIds) => {
  return batchListThroughGetFrom(context, user, stixCyberObservableRelationshipIds, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_OPINION);
};

// region mutations
export const addStixCyberObservableRelationship = async (context, user, stixCyberObservableRelationship) => {
  if (!isStixCyberObservableRelationship(stixCyberObservableRelationship.relationship_type)) {
    throw FunctionalError('Only stix-cyber-observable-relationship can be created through this method.');
  }
  const created = await createRelation(context, user, stixCyberObservableRelationship);
  return notify(BUS_TOPICS[ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP].ADDED_TOPIC, created, user);
};

export const stixCyberObservableRelationshipDelete = async (context, user, stixCyberObservableRelationshipId) => {
  return deleteElementById(context, user, stixCyberObservableRelationshipId, ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP);
};

export const stixCyberObservableRelationshipCleanContext = (context, user, stixCyberObservableRelationshipId) => {
  return stixCoreRelationshipCleanContext(context, user, stixCyberObservableRelationshipId);
};

export const stixCyberObservableRelationshipEditContext = (context, user, stixCyberObservableRelationshipId, input) => {
  return stixCoreRelationshipEditContext(context, user, stixCyberObservableRelationshipId, input);
};

export const stixCyberObservableRelationshipEditField = async (context, user, relationshipId, input) => {
  const { element } = await updateAttribute(context, user, relationshipId, ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP, input);
  return notify(BUS_TOPICS[ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP].EDIT_TOPIC, element, user);
};
// endregion
