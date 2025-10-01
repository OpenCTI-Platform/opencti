import { createEntity } from '../database/middleware';
import { pageEntitiesConnection, loadEntityThroughRelationsPaginated, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_LOCATION_COUNTRY, ENTITY_TYPE_LOCATION_POSITION } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { RELATION_LOCATED_AT } from '../schema/stixCoreRelationship';
import { ValidationError } from '../config/errors';

export const findById = (context, user, positionId) => {
  return storeLoadById(context, user, positionId, ENTITY_TYPE_LOCATION_POSITION);
};

export const findPositionPaginated = (context, user, args) => {
  return pageEntitiesConnection(context, user, [ENTITY_TYPE_LOCATION_POSITION], args);
};

export const locatedAtCity = async (context, user, positionId) => {
  return loadEntityThroughRelationsPaginated(context, user, positionId, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_COUNTRY, false);
};

// Validate coordinates to prevent invalid values
const validateCoordinates = (position) => {
  if (position.latitude !== undefined && position.latitude !== null) {
    const lat = Number(position.latitude);
    if (Number.isNaN(lat) || lat < -90 || lat > 90) {
      throw ValidationError('Latitude must be between -90 and 90 degrees');
    }
  }
  if (position.longitude !== undefined && position.longitude !== null) {
    const lng = Number(position.longitude);
    if (Number.isNaN(lng) || lng < -180 || lng > 180) {
      throw ValidationError('Longitude must be between -180 and 180 degrees');
    }
  }
};

export const addPosition = async (context, user, position) => {
  // Validate coordinates before creating the entity
  validateCoordinates(position);

  const created = await createEntity(
    context,
    user,
    { ...position, x_opencti_location_type: ENTITY_TYPE_LOCATION_POSITION },
    ENTITY_TYPE_LOCATION_POSITION
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
