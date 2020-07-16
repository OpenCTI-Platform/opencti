import { escapeString, findWithConnectedRelations, listEntities, loadEntityById } from '../database/grakn';
import { buildPagination } from '../database/utils';
import {
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  RELATION_PART_OF,
} from '../utils/idGenerator';

export const findById = (individualId) => {
  return loadEntityById(individualId, ENTITY_TYPE_IDENTITY_INDIVIDUAL);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_IDENTITY_INDIVIDUAL], ['name', 'description', 'aliases'], args);
};

export const organizations = (userId) => {
  return findWithConnectedRelations(
    `match $from isa ${ENTITY_TYPE_IDENTITY_INDIVIDUAL};
    $rel(${RELATION_PART_OF}_from:$from, ${RELATION_PART_OF}_to:$to) isa ${RELATION_PART_OF};
    $to isa ${ENTITY_TYPE_IDENTITY_ORGANIZATION}, has internal_id "${escapeString(userId)}"; get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
