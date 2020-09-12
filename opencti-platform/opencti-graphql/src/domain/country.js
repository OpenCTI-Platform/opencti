import { assoc } from 'ramda';
import { createEntity, escapeString, load, listEntities, loadById } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_LOCATION_COUNTRY, ENTITY_TYPE_LOCATION_REGION } from '../schema/stixDomainObject';
import { RELATION_LOCATED_AT } from '../schema/stixCoreRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';

export const findById = (countryId) => {
  return loadById(countryId, ENTITY_TYPE_LOCATION_COUNTRY);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_LOCATION_COUNTRY], ['name', 'description', 'x_opencti_aliases'], args);
};

export const region = async (countryId) => {
  const element = await load(
    `match $to isa ${ENTITY_TYPE_LOCATION_REGION}; 
    $rel(${RELATION_LOCATED_AT}_from:$from, ${RELATION_LOCATED_AT}_to:$to) isa ${RELATION_LOCATED_AT};
    $from has internal_id "${escapeString(countryId)}"; get;`,
    ['to']
  );
  return element && element.to;
};

export const addCountry = async (user, country) => {
  const created = await createEntity(
    user,
    assoc('x_opencti_location_type', ENTITY_TYPE_LOCATION_COUNTRY, country),
    ENTITY_TYPE_LOCATION_COUNTRY,
    { fieldsToUpdate: ['description', 'latitude', 'longitude'] }
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
