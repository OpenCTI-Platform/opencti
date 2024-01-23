import { createEntity } from '../database/middleware';
import { listEntities, loadEntityThroughRelationsPaginated, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_LOCATION_COUNTRY, ENTITY_TYPE_LOCATION_POSITION } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { RELATION_LOCATED_AT } from '../schema/stixCoreRelationship';

export const findById = (context, user, positionId) => {
  return storeLoadById(context, user, positionId, ENTITY_TYPE_LOCATION_POSITION);
};

export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_LOCATION_POSITION], args);
};

export const locatedAtCity = async (context, user, positionId) => {
  return loadEntityThroughRelationsPaginated(context, user, positionId, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_COUNTRY, false);
};

export const addPosition = async (context, user, position) => {
  const created = await createEntity(
    context,
    user,
    { ...position, x_opencti_location_type: ENTITY_TYPE_LOCATION_POSITION },
    ENTITY_TYPE_LOCATION_POSITION
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
