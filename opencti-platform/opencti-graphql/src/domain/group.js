import { assoc } from 'ramda';
import {
  batchListThroughGetFrom,
  batchListThroughGetTo,
  createEntity,
  createRelation,
  deleteElementById,
  deleteRelationsByFromAndTo,
  listThroughGetFrom,
  updateAttribute,
} from '../database/middleware';
import { listEntities, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { ENTITY_TYPE_GROUP, ENTITY_TYPE_USER } from '../schema/internalObject';
import { isInternalRelationship, RELATION_ACCESSES_TO, RELATION_MEMBER_OF } from '../schema/internalRelationship';
import { FunctionalError } from '../config/errors';
import { ABSTRACT_INTERNAL_RELATIONSHIP } from '../schema/general';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { findSessionsForUsers, markSessionForRefresh } from '../database/session';

const groupSessionRefresh = async (context, user, groupId) => {
  const members = await listThroughGetFrom(context, user, [groupId], RELATION_MEMBER_OF, ENTITY_TYPE_USER);
  const sessions = await findSessionsForUsers(members.map((e) => e.internal_id));
  await Promise.all(sessions.map((s) => markSessionForRefresh(s.id)));
};

export const findById = (context, user, groupId) => {
  return storeLoadById(context, user, groupId, ENTITY_TYPE_GROUP);
};

export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_GROUP], args);
};

export const batchMembers = async (context, user, groupIds, opts = {}) => {
  return batchListThroughGetFrom(context, user, groupIds, RELATION_MEMBER_OF, ENTITY_TYPE_USER, opts);
};

export const batchMarkingDefinitions = async (context, user, groupIds) => {
  const opts = { paginate: false };
  return batchListThroughGetTo(context, user, groupIds, RELATION_ACCESSES_TO, ENTITY_TYPE_MARKING_DEFINITION, opts);
};

export const addGroup = async (context, user, group) => {
  const created = await createEntity(context, user, group, ENTITY_TYPE_GROUP);
  return notify(BUS_TOPICS[ENTITY_TYPE_GROUP].ADDED_TOPIC, created, user);
};

export const groupDelete = (context, user, groupId) => {
  return deleteElementById(context, user, groupId, ENTITY_TYPE_GROUP);
};

export const groupEditField = async (context, user, groupId, input) => {
  const { element } = await updateAttribute(context, user, groupId, ENTITY_TYPE_GROUP, input);
  return notify(BUS_TOPICS[ENTITY_TYPE_GROUP].EDIT_TOPIC, element, user);
};

export const groupAddRelation = async (context, user, groupId, input) => {
  const group = await storeLoadById(context, user, groupId, ENTITY_TYPE_GROUP);
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
  const createdRelation = await createRelation(context, user, finalInput);
  await groupSessionRefresh(context, user, groupId);
  return notify(BUS_TOPICS[ENTITY_TYPE_GROUP].EDIT_TOPIC, createdRelation, user);
};

export const groupDeleteRelation = async (context, user, groupId, fromId, toId, relationshipType) => {
  const group = await storeLoadById(context, user, groupId, ENTITY_TYPE_GROUP);
  if (!group) {
    throw FunctionalError('Cannot delete the relation, Group cannot be found.');
  }
  if (!isInternalRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be deleted through this method.`);
  }
  if (fromId) {
    await deleteRelationsByFromAndTo(context, user, fromId, groupId, relationshipType, ABSTRACT_INTERNAL_RELATIONSHIP);
  } else if (toId) {
    await deleteRelationsByFromAndTo(context, user, groupId, toId, relationshipType, ABSTRACT_INTERNAL_RELATIONSHIP);
  }
  await groupSessionRefresh(context, user, groupId);
  return notify(BUS_TOPICS[ENTITY_TYPE_GROUP].EDIT_TOPIC, group, user);
};

export const groupCleanContext = async (context, user, groupId) => {
  await delEditContext(user, groupId);
  return storeLoadById(context, user, groupId, ENTITY_TYPE_GROUP).then((group) => notify(BUS_TOPICS.Group.EDIT_TOPIC, group, user));
};

export const groupEditContext = async (context, user, groupId, input) => {
  await setEditContext(user, groupId, input);
  return storeLoadById(context, user, groupId, ENTITY_TYPE_GROUP).then((group) => notify(BUS_TOPICS.Group.EDIT_TOPIC, group, user));
};
