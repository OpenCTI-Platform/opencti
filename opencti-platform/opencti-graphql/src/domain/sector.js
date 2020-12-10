import { assoc, map } from 'ramda';
import {
  find,
  createEntity,
  escapeString,
  listEntities,
  listThroughGetFroms,
  listThroughGetTos,
  loadById,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_IDENTITY_SECTOR } from '../schema/stixDomainObject';
import { RELATION_PART_OF, RELATION_TARGETS } from '../schema/stixCoreRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { buildPagination } from '../database/utils';

export const findById = (sectorId) => {
  return loadById(sectorId, ENTITY_TYPE_IDENTITY_SECTOR);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_IDENTITY_SECTOR], args);
};

export const batchParentSectors = (sectorIds) => {
  return listThroughGetTos(sectorIds, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_SECTOR);
};

export const batchSubSectors = (sectorIds) => {
  return listThroughGetFroms(sectorIds, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_SECTOR);
};

export const batchIsSubSector = async (sectorIds) => {
  const batchSubsectors = await listThroughGetTos(sectorIds, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_SECTOR);
  return batchSubsectors.map((b) => b.edges.length > 0);
};

// TODO MIGRATE
export const targetedOrganizations = async (sectorId) =>
  find(
    `match $sector has internal_id "${escapeString(sectorId)}";
    $organization isa Organization;
    ($organization, $sector) isa ${RELATION_PART_OF}; 
  $rel($threat, $organization) isa ${RELATION_TARGETS}, has start_time $order;
  get; sort $order desc;`,
    ['rel']
  ).then((data) =>
    buildPagination(
      0,
      0,
      map((n) => ({ node: n.rel }), data),
      data.length
    )
  );

export const addSector = async (user, sector) => {
  const created = await createEntity(
    user,
    assoc('identity_class', ENTITY_TYPE_IDENTITY_SECTOR.toLowerCase(), sector),
    ENTITY_TYPE_IDENTITY_SECTOR
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
