import { assoc } from 'ramda';
import { createEntity, listEntities, loadById, batchLoadThroughGetTo } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_LOCATION_CITY, ENTITY_TYPE_LOCATION_POSITION } from '../schema/stixDomainObject';
import { RELATION_LOCATED_AT } from '../schema/stixCoreRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';

export const findById = (positionId) => {
  return loadById(positionId, ENTITY_TYPE_LOCATION_POSITION);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_LOCATION_POSITION], args);
};

export const batchCity = async (positionIds) => {
  return batchLoadThroughGetTo(positionIds, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_CITY);
};

export const addPosition = async (user, position) => {
  const created = await createEntity(
    user,
    assoc('x_opencti_location_type', ENTITY_TYPE_LOCATION_POSITION, position),
    ENTITY_TYPE_LOCATION_POSITION
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
