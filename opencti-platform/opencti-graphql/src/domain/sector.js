import { assoc, flatten } from 'ramda';
import {
  createEntity,
  listEntities,
  listThroughGetFroms,
  listThroughGetTos,
  loadById,
  listRelations,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION, ENTITY_TYPE_IDENTITY_SECTOR } from '../schema/stixDomainObject';
import { RELATION_PART_OF, RELATION_TARGETS } from '../schema/stixCoreRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';

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

export const targetedOrganizations = async (sectorId) => {
  const opts = { paginate: false, batched: false };
  const organizations = await listThroughGetFroms(sectorId, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_ORGANIZATION, opts);
  const targets = await Promise.all(
    organizations.map((organization) => listRelations(RELATION_TARGETS, { fromId: organization.id }))
  );
  return flatten(targets);
};

export const addSector = async (user, sector) => {
  const created = await createEntity(
    user,
    assoc('identity_class', ENTITY_TYPE_IDENTITY_SECTOR.toLowerCase(), sector),
    ENTITY_TYPE_IDENTITY_SECTOR
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
