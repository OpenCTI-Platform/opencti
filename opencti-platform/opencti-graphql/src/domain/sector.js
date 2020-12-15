import * as R from 'ramda';
import {
  createEntity,
  listEntities,
  batchListThroughGetFrom,
  batchListThroughGetTo,
  loadById,
  listRelations,
  listThroughGetFrom,
  batchLoadThroughGetTo,
} from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION, ENTITY_TYPE_IDENTITY_SECTOR } from '../schema/stixDomainObject';
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
  return batchListThroughGetTo(sectorIds, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_SECTOR);
};

export const batchSubSectors = (sectorIds) => {
  return batchListThroughGetFrom(sectorIds, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_SECTOR);
};

export const batchIsSubSector = async (sectorIds) => {
  const batchSubsectors = await batchLoadThroughGetTo(sectorIds, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_SECTOR);
  return batchSubsectors.map((b) => b !== undefined);
};

export const targetedOrganizations = async (sectorId) => {
  const organizations = await listThroughGetFrom(sectorId, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_ORGANIZATION);
  const targets = await Promise.all(
    organizations.map((organization) => listRelations(RELATION_TARGETS, { fromId: organization.id }))
  );
  const finalTargets = R.pipe(
    R.map((n) => n.edges),
    R.flatten
  )(targets);
  return buildPagination(0, 0, finalTargets, finalTargets.length);
};

export const addSector = async (user, sector) => {
  const created = await createEntity(
    user,
    R.assoc('identity_class', ENTITY_TYPE_IDENTITY_SECTOR.toLowerCase(), sector),
    ENTITY_TYPE_IDENTITY_SECTOR
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
