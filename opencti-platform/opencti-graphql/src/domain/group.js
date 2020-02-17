import {
  createEntity,
  deleteEntityById,
  escapeString,
  executeWrite,
  findWithConnectedRelations,
  listEntities,
  loadEntityById,
  TYPE_OPENCTI_INTERNAL,
  updateAttribute
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { buildPagination } from '../database/utils';

export const findById = groupId => {
  return loadEntityById(groupId, 'Group');
};
export const findAll = args => {
  return listEntities(['Group'], ['name'], args);
};

export const members = async groupId => {
  return findWithConnectedRelations(
    `match $to isa User; $rel(member:$to, grouping:$from) isa membership;
   $from isa Group, has internal_id_key "${escapeString(groupId)}";
   get;`,
    'to',
    'rel'
  ).then(data => buildPagination(0, 0, data, data.length));
};
export const permissions = async groupId => {
  return findWithConnectedRelations(
    `match $to isa Marking-Definition; $rel(allow:$to, allowed:$from) isa permission;
   $from isa Group, has internal_id_key "${escapeString(groupId)}";
   get;`,
    'to',
    'rel'
  ).then(data => buildPagination(0, 0, data, data.length));
};

export const addGroup = async (user, group) => {
  const created = await createEntity(group, 'Group', { modelType: TYPE_OPENCTI_INTERNAL });
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
export const groupDelete = groupId => deleteEntityById(groupId, 'Group');

export const groupEditField = (user, groupId, input) => {
  return executeWrite(wTx => {
    return updateAttribute(groupId, 'Group', input, wTx);
  }).then(async () => {
    const group = await loadEntityById(groupId, 'Group');
    return notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, group, user);
  });
};
