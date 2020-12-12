import { propOr } from 'ramda';
import { stixCoreRelationshipCleanContext, stixCoreRelationshipEditContext } from './stixCoreRelationship';
import { createRelation, deleteElementById, listRelations, loadById, updateAttribute } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP } from '../schema/general';
import { FunctionalError } from '../config/errors';
import { isStixCyberObservableRelationship } from '../schema/stixCyberObservableRelationship';

export const findAll = async (args) =>
  listRelations(propOr(ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP, 'relationship_type', args), args);

export const findById = (stixCyberObservableRelationshipId) => {
  return loadById(stixCyberObservableRelationshipId, ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP);
};

// region mutations
export const addStixCyberObservableRelationship = async (user, stixCyberObservableRelationship) => {
  if (!isStixCyberObservableRelationship(stixCyberObservableRelationship.relationship_type)) {
    throw FunctionalError('Only stix-cyber-observable-relationship can be created trough this method.');
  }
  const created = await createRelation(user, stixCyberObservableRelationship);
  return notify(BUS_TOPICS[ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP].ADDED_TOPIC, created, user);
};

export const stixCyberObservableRelationshipDelete = async (user, stixCyberObservableRelationshipId) => {
  return deleteElementById(user, stixCyberObservableRelationshipId, ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP);
};

export const stixCyberObservableRelationshipCleanContext = (user, stixCyberObservableRelationshipId) =>
  stixCoreRelationshipCleanContext(user, stixCyberObservableRelationshipId);

export const stixCyberObservableRelationshipEditContext = (user, stixCyberObservableRelationshipId, input) =>
  stixCoreRelationshipEditContext(user, stixCyberObservableRelationshipId, input);

export const stixCyberObservableRelationshipEditField = async (user, relationshipId, input) => {
  const stixRelationship = await updateAttribute(
    user,
    relationshipId,
    ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP,
    input
  );
  return notify(BUS_TOPICS.StixCyberObservableRelationship.EDIT_TOPIC, stixRelationship, user);
};
// endregion
