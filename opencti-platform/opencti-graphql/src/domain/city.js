import { assoc } from 'ramda';
import { createEntity, escapeString, listEntities, load, loadById } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_LOCATION_CITY, ENTITY_TYPE_LOCATION_COUNTRY } from '../schema/stixDomainObject';
import { RELATION_LOCATED_AT } from '../schema/stixCoreRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';

export const findById = (cityId) => {
  return loadById(cityId, ENTITY_TYPE_LOCATION_CITY);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_LOCATION_CITY], ['name', 'description', 'x_opencti_aliases'], args);
};

export const country = async (cityId) => {
  const element = await load(
    `match $to isa ${ENTITY_TYPE_LOCATION_COUNTRY}; 
    $rel(${RELATION_LOCATED_AT}_from:$from, ${RELATION_LOCATED_AT}_to:$to) isa ${RELATION_LOCATED_AT};
    $from has internal_id "${escapeString(cityId)}"; get;`,
    ['to']
  );
  return element && element.to;
};

export const addCity = async (user, city) => {
  const created = await createEntity(
    user,
    assoc('x_opencti_location_type', ENTITY_TYPE_LOCATION_CITY, city),
    ENTITY_TYPE_LOCATION_CITY
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
