import { assoc, concat } from 'ramda';
import {
  createEntity,
  escapeString,
  getSingleValueNumber,
  listEntities,
  loadEntityById,
  TYPE_STIX_DOMAIN_ENTITY
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { findAll as findAllMarkingDef } from './markingDefinition';

export const findById = sectorId => {
  return loadEntityById(sectorId);
};
export const findAll = args => {
  const typedArgs = assoc('types', ['Sector'], args);
  return listEntities(['name', 'alias'], typedArgs);
};

export const markingDefinitions = (sectorId, args) => {
  const filters = concat([{ key: 'object_marking_refs.internal_id_key', values: [sectorId] }], args.filters || []);
  const filterArgs = assoc('filters', filters, args);
  return findAllMarkingDef(filterArgs);
};
export const subsectors = (sectorId, args) => {
  const subFilter = { key: 'gathering.internal_id_key', values: [sectorId], sourceRole: 'part_of' };
  const filters = concat([subFilter], args.filters || []);
  const filterArgs = assoc('filters', filters, args);
  return findAll(filterArgs);
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
