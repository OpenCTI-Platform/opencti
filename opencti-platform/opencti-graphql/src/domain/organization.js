import { assoc, isNil, map } from 'ramda';
import {
  createEntity,
  listEntities,
  listToEntitiesThroughRelation,
  loadById,
  updateAttribute,
} from '../database/grakn';
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

export const sectors = (organizationId) => {
  return listToEntitiesThroughRelation(organizationId, null, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_SECTOR);
};

export const addOrganization = async (user, organization) => {
  const created = await createEntity(
    user,
    assoc('identity_class', ENTITY_TYPE_IDENTITY_ORGANIZATION.toLowerCase(), organization),
    ENTITY_TYPE_IDENTITY_ORGANIZATION
  );
  if (organization.update === true) {
    const fieldsToUpdate = ['description', 'x_opencti_organization_type', 'x_opencti_reliability'];
    await Promise.all(
      map((field) => {
        if (!isNil(organization[field])) {
          return updateAttribute(user, created.id, created.entity_type, { key: field, value: [organization[field]] });
        }
        return true;
      }, fieldsToUpdate)
    );
  }
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
