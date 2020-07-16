import { escapeString, findWithConnectedRelations, listEntities, loadEntityById } from '../database/grakn';
import { buildPagination } from '../database/utils';
import { ENTITY_TYPE_IDENTITY_INDIVIDUAL } from '../utils/idGenerator';

export const findById = (individualId) => {
  return loadEntityById(individualId, ENTITY_TYPE_IDENTITY_INDIVIDUAL);
};
export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_IDENTITY_INDIVIDUAL], ['name', 'description', 'aliases'], args);
};
export const individuals = (userId) => {
  return findWithConnectedRelations(
    `match $to isa Individual; $rel(part_of:$from, gather:$to) isa gathering;
     $from isa User, has internal_id "${escapeString(userId)}"; get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};