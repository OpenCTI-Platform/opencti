import { pipe, assoc, dissoc, filter, map, isNil } from 'ramda';
import { createEntity, listEntities, loadById, updateAttribute } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ABSTRACT_STIX_DOMAIN_OBJECT, ENTITY_TYPE_LOCATION } from '../schema/general';
import { isStixDomainObjectLocation } from '../schema/stixDomainObject';

export const findById = async (locationId) => {
  return loadById(locationId, ENTITY_TYPE_LOCATION);
};

export const findAll = async (args) => {
  let types = [];
  if (args.types && args.types.length > 0) {
    types = filter((type) => isStixDomainObjectLocation(type), args.types);
  }
  if (types.length === 0) {
    types.push(ENTITY_TYPE_LOCATION);
  }
  return listEntities(types, ['name', 'description', 'aliases'], args);
};

export const addLocation = async (user, location) => {
  const locationToCreate = pipe(assoc('x_opencti_location_type', location.type), dissoc('type'))(location);
  const created = await createEntity(user, locationToCreate, location.type);
  if (location.update === true) {
    const fieldsToUpdate = ['description', 'longitude', 'latitude'];
    await Promise.all(
      map((field) => {
        if (!isNil(location[field])) {
          return updateAttribute(user, created.id, created.entity_type, { key: field, value: [location[field]] });
        }
        return true;
      }, fieldsToUpdate)
    );
  }
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
