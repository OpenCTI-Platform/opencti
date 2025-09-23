import { assoc } from 'ramda';
import { createEntity } from '../database/middleware';
import { pageEntitiesConnection, pageRegardingEntitiesConnection, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_IDENTITY_SYSTEM } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { RELATION_BELONGS_TO } from '../schema/stixCoreRelationship';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../modules/organization/organization-types';

export const findById = (context, user, systemId) => {
  return storeLoadById(context, user, systemId, ENTITY_TYPE_IDENTITY_SYSTEM);
};

export const findSystemPaginated = (context, user, args) => {
  return pageEntitiesConnection(context, user, [ENTITY_TYPE_IDENTITY_SYSTEM], args);
};

export const addSystem = async (context, user, system) => {
  const created = await createEntity(
    context,
    user,
    assoc('identity_class', ENTITY_TYPE_IDENTITY_SYSTEM.toLowerCase(), system),
    ENTITY_TYPE_IDENTITY_SYSTEM
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const belongsToOrganizationsPaginated = async (context, user, stixCoreObjectId, opts) => {
  return pageRegardingEntitiesConnection(context, user, stixCoreObjectId, RELATION_BELONGS_TO, ENTITY_TYPE_IDENTITY_ORGANIZATION, false, opts);
};
