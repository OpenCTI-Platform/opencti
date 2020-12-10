import { assoc } from 'ramda';
import { createEntity, listEntities, listThroughGetTos, loadById } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION, ENTITY_TYPE_IDENTITY_SECTOR } from '../schema/stixDomainObject';
import { RELATION_PART_OF } from '../schema/stixCoreRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';

export const findById = (organizationId) => {
  return loadById(organizationId, ENTITY_TYPE_IDENTITY_ORGANIZATION);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_IDENTITY_ORGANIZATION], ['name', 'x_opencti_aliases'], args);
};

export const batchSectors = (organizationIds) => {
  return listThroughGetTos(organizationIds, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_SECTOR);
};

export const addOrganization = async (user, organization) => {
  const created = await createEntity(
    user,
    assoc('identity_class', ENTITY_TYPE_IDENTITY_ORGANIZATION.toLowerCase(), organization),
    ENTITY_TYPE_IDENTITY_ORGANIZATION
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
