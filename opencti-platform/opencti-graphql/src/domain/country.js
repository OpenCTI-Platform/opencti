import {
  createEntity,
  escapeString,
  listEntities,
  loadEntityById,
  loadWithConnectedRelations,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_LOCATION_COUNTRY, ENTITY_TYPE_LOCATION_REGION, RELATION_LOCATED_AT } from '../utils/idGenerator';

export const findById = (countryId) => {
  return loadEntityById(countryId, ENTITY_TYPE_LOCATION_COUNTRY);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_LOCATION_COUNTRY], ['name', 'description', 'x_opencti_aliases'], args);
};

export const region = (countryId) => {
  return loadWithConnectedRelations(
    `match $to isa ${ENTITY_TYPE_LOCATION_REGION}; 
    $rel(${RELATION_LOCATED_AT}_from:$from, ${RELATION_LOCATED_AT}_to:$to) isa ${RELATION_LOCATED_AT};
    $from has internal_id "${escapeString(countryId)}"; get; offset 0; limit 1;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => (data ? data.node : undefined));
};

export const addCountry = async (user, country) => {
  const created = await createEntity(user, country, ENTITY_TYPE_LOCATION_COUNTRY);
  return notify(BUS_TOPICS.stixDomainObject.ADDED_TOPIC, created, user);
};
