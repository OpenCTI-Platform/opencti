import { assoc } from 'ramda';
import {
  createEntity,
  escapeString,
  getSingleValueNumber,
  loadEntityById,
  paginate,
  TYPE_STIX_DOMAIN_ENTITY
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { elPaginate } from '../database/elasticSearch';
import { notify } from '../database/redis';

export const findById = sectorId => {
  return loadEntityById(sectorId);
};
export const findAll = args => {
  return elPaginate('stix_domain_entities', assoc('type', 'sector', args));
};

// region grakn fetch
export const markingDefinitions = (sectorId, args) => {
  return paginate(
    `match $marking isa Marking-Definition; 
    $rel(marking:$marking, so:$s) isa object_marking_refs; 
    $s has internal_id_key "${escapeString(sectorId)}"`,
    args
  );
};
export const subsectors = (sectorId, args) => {
  return paginate(
    `match $subsector isa Sector; 
    $rel(gather:$s, part_of:$subsector) isa gathering; 
    $s has internal_id_key "${escapeString(sectorId)}"`,
    args
  );
};
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

export const addSector = async (user, sector) => {
  const created = await createEntity(sector, 'Sector', TYPE_STIX_DOMAIN_ENTITY, 'identity');
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
