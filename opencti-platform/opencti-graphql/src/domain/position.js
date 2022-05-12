import { assoc } from 'ramda';
import { createEntity, storeLoadById, batchLoadThroughGetTo } from '../database/middleware';
import { listEntities } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_LOCATION_CITY, ENTITY_TYPE_LOCATION_POSITION } from '../schema/stixDomainObject';
import { RELATION_LOCATED_AT } from '../schema/stixCoreRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';

export const findById = (user, positionId) => {
  return storeLoadById(user, positionId, ENTITY_TYPE_LOCATION_POSITION);
};

export const findAll = (user, args) => {
  return listEntities(user, [ENTITY_TYPE_LOCATION_POSITION], args);
};

export const batchCity = async (user, positionIds) => {
  return batchLoadThroughGetTo(user, positionIds, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_CITY);
};

export const addPosition = async (user, position) => {
  const created = await createEntity(
    user,
    assoc('x_opencti_location_type', ENTITY_TYPE_LOCATION_POSITION, position),
    ENTITY_TYPE_LOCATION_POSITION
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
