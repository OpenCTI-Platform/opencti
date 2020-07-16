import { assoc, pipe } from 'ramda';
import {
  createEntity,
  createRelation,
  deleteEntityById,
  deleteRelationById,
  escapeString,
  executeWrite,
  findWithConnectedRelations,
  listEntities,
  loadEntityById,
  updateAttribute,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { buildPagination } from '../database/utils';
import { ENTITY_TYPE_GROUP } from '../utils/idGenerator';

export const findById = (groupId) => {
  return loadEntityById(groupId, ENTITY_TYPE_GROUP);
};
export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_GROUP], ['name'], args);
};

export const members = async (groupId) => {
  return findWithConnectedRelations(
    `match $to isa User; $rel(member:$to, grouping:$from) isa membership;
   $from isa Group, has internal_id "${escapeString(groupId)}";
   get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
export const permissions = async (groupId) => {
  return findWithConnectedRelations(
    `match $to isa Marking-Definition; $rel(allow:$to, allowed:$from) isa permission;
   $from isa Group, has internal_id "${escapeString(groupId)}";
   get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const addGroup = async (user, group) => {
  const created = await createEntity(user, group, ENTITY_TYPE_GROUP, { noLog: true });
  return notify(BUS_TOPICS.Group.ADDED_TOPIC, created, user);
};
export const groupDelete = (user, groupId) => deleteEntityById(user, groupId, ENTITY_TYPE_GROUP, { noLog: true });

export const groupEditField = (user, groupId, input) => {
  return executeWrite((wTx) => {
    return updateAttribute(user, groupId, ENTITY_TYPE_GROUP, input, wTx, { noLog: true });
  }).then(async () => {
    const group = await loadEntityById(groupId, ENTITY_TYPE_GROUP);
    return notify(BUS_TOPICS.Group.EDIT_TOPIC, group, user);
  });
};

export const groupAddRelation = async (user, groupId, input) => {
  const finalInput = pipe(assoc('fromId', groupId), assoc('fromType', ENTITY_TYPE_GROUP))(input);
  const data = await createRelation(user, finalInput, { noLog: true });
  return notify(BUS_TOPICS.Group.EDIT_TOPIC, data, user);
};

export const groupDeleteRelation = async (user, groupId, relationId) => {
  await deleteRelationById(user, relationId, 'relation');
  const data = await loadEntityById(groupId, ENTITY_TYPE_GROUP);
  return notify(BUS_TOPICS.Group.EDIT_TOPIC, data, user);
};

export const groupCleanContext = (user, groupId) => {
  delEditContext(user, groupId);
  return loadEntityById(groupId, ENTITY_TYPE_GROUP).then((group) => notify(BUS_TOPICS.Group.EDIT_TOPIC, group, user));
};
export const groupEditContext = (user, groupId, input) => {
  setEditContext(user, groupId, input);
  return loadEntityById(groupId, ENTITY_TYPE_GROUP).then((group) => notify(BUS_TOPICS.Group.EDIT_TOPIC, group, user));
};
