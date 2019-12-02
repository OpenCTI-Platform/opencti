import { assoc } from 'ramda';
import {
  createEntity,
  escapeString,
  findWithConnectedRelations,
  getSingleValueNumber,
  listEntities,
  loadEntityById,
  loadEntityByStixId,
  TYPE_STIX_DOMAIN_ENTITY
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { buildPagination } from '../database/utils';

export const findById = sectorId => {
  if (sectorId.match(/[a-z-]+--[\w-]{36}/g)) {
    return loadEntityByStixId(sectorId);
  }
  return loadEntityById(sectorId);
};
export const findAll = args => {
  const typedArgs = assoc('types', ['Sector'], args);
  return listEntities(['name', 'alias'], typedArgs);
};
export const subsectors = sectorId => {
  return findWithConnectedRelations(
    `match $to isa Sector; $rel(gather:$from, part_of:$to) isa gathering;
     $from has internal_id_key "${escapeString(sectorId)}"; get;`,
    'to',
    'rel'
  ).then(data => buildPagination(0, 0, data, data.length));
};

export const addSector = async (user, sector) => {
  const created = await createEntity(sector, 'Sector', { modelType: TYPE_STIX_DOMAIN_ENTITY, stixIdType: 'identity' });
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};

// region metrics and counting
export const isSubsector = async (sectorId, args) => {
  const numberOfParents = await getSingleValueNumber(
    `match $parent isa Sector; 
    $rel(gather:$parent, part_of:$subsector) isa gathering; 
    $subsector has internal_id_key "${escapeString(sectorId)}"; get; count;`,
    args
  );
  return numberOfParents > 0;
};
// endregion
