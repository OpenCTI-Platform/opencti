import {
  createEntity,
  escapeString,
  findWithConnectedRelations,
  getSingleValueNumber,
  listEntities,
  loadEntityById,
  loadEntityByStixId,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { buildPagination, TYPE_STIX_DOMAIN_ENTITY } from '../database/utils';

export const findById = (sectorId) => {
  if (sectorId.match(/[a-z-]+--[\w-]{36}/g)) {
    return loadEntityByStixId(sectorId, 'Sector');
  }
  return loadEntityById(sectorId, 'Sector');
};
export const findAll = (args) => {
  return listEntities(['Sector'], ['name', 'alias'], args);
};
export const parentSectors = (sectorId) => {
  return findWithConnectedRelations(
    `match $to isa Sector; $rel(part_of:$from, gather:$to) isa gathering;
     $from has internal_id_key "${escapeString(sectorId)}"; get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
export const subSectors = (sectorId) => {
  return findWithConnectedRelations(
    `match $to isa Sector; $rel(gather:$from, part_of:$to) isa gathering;
     $from has internal_id_key "${escapeString(sectorId)}"; get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const isSubSector = async (sectorId, args) => {
  const numberOfParents = await getSingleValueNumber(
    `match $parent isa Sector; 
    $rel(gather:$parent, part_of:$subsector) isa gathering; 
    $subsector has internal_id_key "${escapeString(sectorId)}"; get; count;`,
    args
  );
  return numberOfParents > 0;
};
export const addSector = async (user, sector) => {
  const created = await createEntity(user, sector, 'Sector', { modelType: TYPE_STIX_DOMAIN_ENTITY, stixIdType: 'identity' });
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
