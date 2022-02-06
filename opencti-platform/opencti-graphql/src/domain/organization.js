import { assoc } from 'ramda';
import { createEntity, batchListThroughGetTo, loadById } from '../database/middleware';
import { listEntities } from '../database/repository';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION, ENTITY_TYPE_IDENTITY_SECTOR } from '../schema/stixDomainObject';
import { RELATION_PART_OF } from '../schema/stixCoreRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';

export const findById = (user, organizationId) => {
  return loadById(user, organizationId, ENTITY_TYPE_IDENTITY_ORGANIZATION);
};

export const findAll = (user, args) => {
  return listEntities(user, [ENTITY_TYPE_IDENTITY_ORGANIZATION], args);
};

export const batchSectors = (user, organizationIds) => {
  return batchListThroughGetTo(user, organizationIds, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_SECTOR);
};

export const addOrganization = async (user, organization) => {
  const created = await createEntity(
    user,
    assoc('identity_class', ENTITY_TYPE_IDENTITY_ORGANIZATION.toLowerCase(), organization),
    ENTITY_TYPE_IDENTITY_ORGANIZATION
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
