import * as R from 'ramda';
import { createEntity } from '../database/middleware';
import { listAllFromEntitiesThroughRelations, listEntities, listEntitiesThroughRelationsPaginated, listRelations, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_IDENTITY_SECTOR } from '../schema/stixDomainObject';
import { RELATION_PART_OF, RELATION_TARGETS } from '../schema/stixCoreRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { buildPagination } from '../database/utils';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../modules/organization/organization-types';

export const findById = (context, user, sectorId) => {
  return storeLoadById(context, user, sectorId, ENTITY_TYPE_IDENTITY_SECTOR);
};

export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_IDENTITY_SECTOR], args);
};

export const parentSectorsPaginated = async (context, user, groupId, args) => {
  return listEntitiesThroughRelationsPaginated(context, user, groupId, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_SECTOR, false, false, args);
};

export const childSectorsPaginated = async (context, user, groupId, args) => {
  return listEntitiesThroughRelationsPaginated(context, user, groupId, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_SECTOR, true, false, args);
};

export const isSubSector = async (context, user, sectorId) => {
  const pagination = await parentSectorsPaginated(context, user, sectorId, { first: 1 });
  return pagination.edges.length > 0;
};

export const targetedOrganizations = async (context, user, sectorId) => {
  const organizations = await listAllFromEntitiesThroughRelations(context, user, sectorId, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_ORGANIZATION);
  const targets = await Promise.all(
    organizations.map((organization) => listRelations(context, user, RELATION_TARGETS, { fromId: organization.id }))
  );
  const finalTargets = R.pipe(
    R.map((n) => n.edges),
    R.flatten
  )(targets);
  return buildPagination(0, 0, finalTargets, finalTargets.length);
};

export const addSector = async (context, user, sector) => {
  const created = await createEntity(context, user, R.assoc('identity_class', 'class', sector), ENTITY_TYPE_IDENTITY_SECTOR);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
