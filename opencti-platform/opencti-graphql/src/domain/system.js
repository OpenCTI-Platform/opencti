import { assoc } from 'ramda';
import { createEntity, batchListThroughGetTo, storeLoadById } from '../database/middleware';
import { listEntities } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_IDENTITY_SYSTEM, ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { RELATION_BELONGS_TO } from '../schema/stixCoreRelationship';

export const findById = (user, systemId) => {
  return storeLoadById(user, systemId, ENTITY_TYPE_IDENTITY_SYSTEM);
};

export const findAll = (user, args) => {
  return listEntities(user, [ENTITY_TYPE_IDENTITY_SYSTEM], args);
};

export const addSystem = async (user, system) => {
  const created = await createEntity(
    user,
    assoc('identity_class', ENTITY_TYPE_IDENTITY_SYSTEM.toLowerCase(), system),
    ENTITY_TYPE_IDENTITY_SYSTEM
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const batchOrganizations = (user, systemIds) => {
  return batchListThroughGetTo(user, systemIds, RELATION_BELONGS_TO, ENTITY_TYPE_IDENTITY_ORGANIZATION);
};
