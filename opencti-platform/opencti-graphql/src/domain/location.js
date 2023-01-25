import * as R from 'ramda';
import { createEntity } from '../database/middleware';
import { listEntities, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ABSTRACT_STIX_DOMAIN_OBJECT, ENTITY_TYPE_LOCATION } from '../schema/general';
import { isStixDomainObjectLocation } from '../schema/stixDomainObject';
import { FunctionalError } from '../config/errors';
import { schemaAttributesDefinition } from '../schema/schema-attributes';

export const findById = async (context, user, locationId) => {
  return storeLoadById(context, user, locationId, ENTITY_TYPE_LOCATION);
};

export const findAll = async (context, user, args) => {
  let types = [];
  if (args.types && args.types.length > 0) {
    types = args.types.filter((type) => isStixDomainObjectLocation(type));
  }
  if (types.length === 0) {
    types.push(ENTITY_TYPE_LOCATION);
  }
  return listEntities(context, user, types, args);
};

export const addLocation = async (context, user, location) => {
  const { type } = location;
  if (!isStixDomainObjectLocation(type)) {
    const supportedTypes = schemaAttributesDefinition.get(ENTITY_TYPE_LOCATION).join(', ');
    throw FunctionalError(`Invalid location type ${type}, please provide one of ${supportedTypes}`);
  }
  const locationToCreate = R.pipe(
    R.assoc('x_opencti_location_type', location.type),
    R.dissoc('type')
  )(location);
  const created = await createEntity(context, user, locationToCreate, type);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
