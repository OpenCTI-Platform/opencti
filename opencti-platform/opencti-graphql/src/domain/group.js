import { assoc } from 'ramda';
import {
  createEntity,
  createRelation,
  deleteElementById,
  deleteRelationsByFromAndTo,
  batchListThroughGetFrom,
  batchListThroughGetTo,
  storeLoadById,
  updateAttribute,
} from '../database/middleware';
import { listEntities } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { ENTITY_TYPE_GROUP, ENTITY_TYPE_USER } from '../schema/internalObject';
import { isInternalRelationship, RELATION_ACCESSES_TO, RELATION_MEMBER_OF } from '../schema/internalRelationship';
import { FunctionalError } from '../config/errors';
import { ABSTRACT_INTERNAL_RELATIONSHIP } from '../schema/general';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';

export const findById = (user, groupId) => {
  return storeLoadById(user, groupId, ENTITY_TYPE_GROUP);
};

export const findAll = (user, args) => {
  return listEntities(user, [ENTITY_TYPE_GROUP], args);
};

export const batchMembers = async (user, groupIds) => {
  return batchListThroughGetFrom(user, groupIds, RELATION_MEMBER_OF, ENTITY_TYPE_USER);
};

export const batchMarkingDefinitions = async (user, groupIds) => {
  const opts = { paginate: false };
  return batchListThroughGetTo(user, groupIds, RELATION_ACCESSES_TO, ENTITY_TYPE_MARKING_DEFINITION, opts);
};

export const addGroup = async (user, group) => {
  const created = await createEntity(user, group, ENTITY_TYPE_GROUP);
  return notify(BUS_TOPICS[ENTITY_TYPE_GROUP].ADDED_TOPIC, created, user);
};

export const groupDelete = (user, groupId) => deleteElementById(user, groupId, ENTITY_TYPE_GROUP);

export const groupEditField = async (user, groupId, input) => {
  const { element } = await updateAttribute(user, groupId, ENTITY_TYPE_GROUP, input);
  return notify(BUS_TOPICS[ENTITY_TYPE_GROUP].EDIT_TOPIC, element, user);
};

export const groupAddRelation = async (user, groupId, input) => {
  const group = await storeLoadById(user, groupId, ENTITY_TYPE_GROUP);
  if (!group) {
    throw FunctionalError('Cannot add the relation, Group cannot be found.');
  }
  if (!isInternalRelationship(input.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be added through this method.`);
  }
  let finalInput;
  if (input.fromId) {
    finalInput = assoc('toId', groupId, input);
  } else if (input.toId) {
    finalInput = assoc('fromId', groupId, input);
  }
  return createRelation(user, finalInput).then((relationData) => {
    notify(BUS_TOPICS[ENTITY_TYPE_GROUP].EDIT_TOPIC, relationData, user);
    return relationData;
  });
};

export const groupDeleteRelation = async (user, groupId, fromId, toId, relationshipType) => {
  const group = await storeLoadById(user, groupId, ENTITY_TYPE_GROUP);
  if (!group) {
    throw FunctionalError('Cannot delete the relation, Group cannot be found.');
  }
  if (!isInternalRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be deleted through this method.`);
  }
  if (fromId) {
    await deleteRelationsByFromAndTo(user, fromId, groupId, relationshipType, ABSTRACT_INTERNAL_RELATIONSHIP);
  } else if (toId) {
    await deleteRelationsByFromAndTo(user, groupId, toId, relationshipType, ABSTRACT_INTERNAL_RELATIONSHIP);
  }
  return notify(BUS_TOPICS[ENTITY_TYPE_GROUP].EDIT_TOPIC, group, user);
};

export const groupCleanContext = async (user, groupId) => {
  await delEditContext(user, groupId);
  return storeLoadById(user, groupId, ENTITY_TYPE_GROUP).then((group) => notify(BUS_TOPICS.Group.EDIT_TOPIC, group, user));
};

export const groupEditContext = async (user, groupId, input) => {
  await setEditContext(user, groupId, input);
  return storeLoadById(user, groupId, ENTITY_TYPE_GROUP).then((group) => notify(BUS_TOPICS.Group.EDIT_TOPIC, group, user));
};
