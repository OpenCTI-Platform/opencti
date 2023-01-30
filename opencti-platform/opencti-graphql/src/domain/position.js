import { createEntity, batchLoadThroughGetTo } from '../database/middleware';
import { listEntities, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_LOCATION_CITY, ENTITY_TYPE_LOCATION_POSITION } from '../schema/stixDomainObject';
import { RELATION_LOCATED_AT } from '../schema/stixCoreRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';

export const findById = (context, user, positionId) => {
  return storeLoadById(context, user, positionId, ENTITY_TYPE_LOCATION_POSITION);
};

export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_LOCATION_POSITION], args);
};

export const batchCity = async (context, user, positionIds) => {
  return batchLoadThroughGetTo(context, user, positionIds, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_CITY);
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
