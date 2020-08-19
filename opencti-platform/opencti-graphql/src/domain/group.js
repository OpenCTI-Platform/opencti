import { assoc, pipe } from 'ramda';
import {
  createEntity,
  createRelation,
  deleteEntityById,
  deleteRelationById,
  deleteRelationsByFromAndTo,
  executeWrite,
  listEntities,
  listFromEntitiesThroughRelation,
  loadEntityById,
  updateAttribute,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  ABSTRACT_INTERNAL_RELATIONSHIP,
  ABSTRACT_STIX_DOMAIN_OBJECT,
  ABSTRACT_STIX_META_RELATIONSHIP,
  ENTITY_TYPE_GROUP,
  ENTITY_TYPE_USER,
  isInternalRelationship,
  isStixMetaRelationship,
  RELATION_MEMBER_OF,
} from '../utils/idGenerator';
import { FunctionalError } from '../config/errors';

export const findById = (groupId) => {
  return loadEntityById(groupId, ENTITY_TYPE_GROUP);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_GROUP], ['name'], args);
};

export const members = async (groupId) => {
  return listFromEntitiesThroughRelation(groupId, ENTITY_TYPE_GROUP, RELATION_MEMBER_OF, ENTITY_TYPE_USER);
};

export const addGroup = async (user, group) => {
  const created = await createEntity(user, group, ENTITY_TYPE_GROUP, { noLog: true });
  return notify(BUS_TOPICS[ENTITY_TYPE_GROUP].ADDED_TOPIC, created, user);
};

export const groupDelete = (user, groupId) => deleteEntityById(user, groupId, ENTITY_TYPE_GROUP, { noLog: true });

export const groupEditField = (user, groupId, input) => {
  return executeWrite((wTx) => {
    return updateAttribute(user, groupId, ENTITY_TYPE_GROUP, input, wTx, { noLog: true });
  }).then(async () => {
    const group = await loadEntityById(groupId, ENTITY_TYPE_GROUP);
    return notify(BUS_TOPICS[ENTITY_TYPE_GROUP].EDIT_TOPIC, group, user);
  });
};

export const groupAddRelation = async (user, groupId, input) => {
  const group = await loadEntityById(groupId, ENTITY_TYPE_GROUP);
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
  return createRelation(user, finalInput, { noLog: true }).then((relationData) => {
    notify(BUS_TOPICS[ENTITY_TYPE_GROUP].EDIT_TOPIC, relationData, user);
    return relationData;
  });
};

export const groupDeleteRelation = async (user, groupId, fromId, toId, relationshipType) => {
  const group = await loadEntityById(groupId, ENTITY_TYPE_GROUP);
  if (!group) {
    throw FunctionalError('Cannot delete the relation, Group cannot be found.');
  }
  if (!isInternalRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be deleted through this method.`);
  }
  if (fromId) {
    await deleteRelationsByFromAndTo(user, fromId, groupId, relationshipType, ABSTRACT_INTERNAL_RELATIONSHIP, {
      noLog: true,
    });
  } else if (toId) {
    await deleteRelationsByFromAndTo(user, groupId, toId, relationshipType, ABSTRACT_INTERNAL_RELATIONSHIP, {
      noLog: true,
    });
  }
  return notify(BUS_TOPICS[ENTITY_TYPE_GROUP].EDIT_TOPIC, group, user);
};

export const groupCleanContext = async (user, groupId) => {
  await delEditContext(user, groupId);
  return loadEntityById(groupId, ENTITY_TYPE_GROUP).then((group) => notify(BUS_TOPICS.Group.EDIT_TOPIC, group, user));
};

export const groupEditContext = async (user, groupId, input) => {
  await setEditContext(user, groupId, input);
  return loadEntityById(groupId, ENTITY_TYPE_GROUP).then((group) => notify(BUS_TOPICS.Group.EDIT_TOPIC, group, user));
};
