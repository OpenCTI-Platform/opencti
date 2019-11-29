import { assoc } from 'ramda';
import {
  createEntity,
  deleteEntityById,
  escapeString,
  findWithConnectedRelations,
  listEntities,
  loadEntityById,
  TYPE_OPENCTI_INTERNAL
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { buildPagination } from '../database/utils';

export const findById = groupId => {
  return loadEntityById(groupId);
};
export const findAll = args => {
  const typedArgs = assoc('types', ['Group'], args);
  return listEntities(['name'], typedArgs);
};

export const members = async groupId => {
  return findWithConnectedRelations(
    `match $to isa User; $rel(member:$to, grouping:$from) isa membership;
   $from has internal_id_key "${escapeString(groupId)}";
   get;`,
    'to',
    'rel'
  ).then(data => buildPagination(0, 0, data, data.length));
};
export const groups = userId => {
  return findWithConnectedRelations(
    `match $from isa User; $rel(member:$from, grouping:$to) isa membership;
   $from has internal_id_key "${escapeString(userId)}";
   get;`,
    'to',
    'rel'
  ).then(data => buildPagination(0, 0, data, data.length));
};
export const permissions = async groupId => {
  return findWithConnectedRelations(
    `match $to isa Marking-Definition; $rel(allow:$to, allowed:$from) isa permission;
   $from has internal_id_key "${escapeString(groupId)}";
   get;`,
    'to',
    'rel'
  ).then(data => buildPagination(0, 0, data, data.length));
};

export const addGroup = async (user, group) => {
  const created = await createEntity(group, 'Group', { modelType: TYPE_OPENCTI_INTERNAL });
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
export const groupDelete = groupId => deleteEntityById(groupId);
