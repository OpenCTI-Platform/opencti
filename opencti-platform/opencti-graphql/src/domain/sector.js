import { assoc } from 'ramda';
import {
  createEntity,
  escapeString,
  getSingleValueNumber,
  listEntities,
  listFromEntitiesThroughRelation,
  listToEntitiesThroughRelation,
  loadEntityById,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ABSTRACT_STIX_DOMAIN_OBJECT, ENTITY_TYPE_IDENTITY_SECTOR, RELATION_PART_OF } from '../utils/idGenerator';

export const findById = (sectorId) => {
  return loadEntityById(sectorId, ENTITY_TYPE_IDENTITY_SECTOR);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_IDENTITY_SECTOR], ['name', 'x_opencti_aliases'], args);
};

export const parentSectors = (sectorId) => {
  return listToEntitiesThroughRelation(sectorId, null, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_SECTOR);
};

export const subSectors = (sectorId) => {
  return listFromEntitiesThroughRelation(sectorId, null, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_SECTOR);
};

export const isSubSector = async (sectorId, args) => {
  const numberOfParents = await getSingleValueNumber(
    `match $parent isa ${ENTITY_TYPE_IDENTITY_SECTOR}; 
    $rel(${RELATION_PART_OF}_from:$subsector, ${RELATION_PART_OF}_to:$parent) isa ${RELATION_PART_OF}; 
    $subsector has internal_id "${escapeString(sectorId)}"; get; count;`,
    args
  );
  return numberOfParents > 0;
};

export const addSector = async (user, sector) => {
  const created = await createEntity(
    user,
    assoc('identity_class', ENTITY_TYPE_IDENTITY_SECTOR.toLowerCase(), sector),
    ENTITY_TYPE_IDENTITY_SECTOR
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
