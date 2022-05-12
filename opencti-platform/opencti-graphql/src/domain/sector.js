import * as R from 'ramda';
import {
  createEntity,
  batchListThroughGetFrom,
  batchListThroughGetTo,
  storeLoadById,
  listThroughGetFrom,
  batchLoadThroughGetTo,
} from '../database/middleware';
import { listEntities, listRelations } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION, ENTITY_TYPE_IDENTITY_SECTOR } from '../schema/stixDomainObject';
import { RELATION_PART_OF, RELATION_TARGETS } from '../schema/stixCoreRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { buildPagination } from '../database/utils';

export const findById = (user, sectorId) => {
  return storeLoadById(user, sectorId, ENTITY_TYPE_IDENTITY_SECTOR);
};

export const findAll = (user, args) => {
  return listEntities(user, [ENTITY_TYPE_IDENTITY_SECTOR], args);
};

export const batchParentSectors = (user, sectorIds) => {
  return batchListThroughGetTo(user, sectorIds, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_SECTOR);
};

export const batchSubSectors = (user, sectorIds) => {
  return batchListThroughGetFrom(user, sectorIds, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_SECTOR);
};

export const batchIsSubSector = async (user, sectorIds) => {
  const batchSubsectors = await batchLoadThroughGetTo(user, sectorIds, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_SECTOR);
  return batchSubsectors.map((b) => b !== undefined);
};

export const targetedOrganizations = async (user, sectorId) => {
  const organizations = await listThroughGetFrom(user, sectorId, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_ORGANIZATION);
  const targets = await Promise.all(
    organizations.map((organization) => listRelations(user, RELATION_TARGETS, { fromId: organization.id }))
  );
  const finalTargets = R.pipe(
    R.map((n) => n.edges),
    R.flatten
  )(targets);
  return buildPagination(0, 0, finalTargets, finalTargets.length);
};

export const addSector = async (user, sector) => {
  const created = await createEntity(user, R.assoc('identity_class', 'class', sector), ENTITY_TYPE_IDENTITY_SECTOR);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
