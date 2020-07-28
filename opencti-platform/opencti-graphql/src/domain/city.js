import {
  createEntity,
  escapeString,
  listEntities,
  loadEntityById,
  loadWithConnectedRelations,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import {
  ABSTRACT_STIX_DOMAIN_OBJECT,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  RELATION_LOCATED_AT,
} from '../utils/idGenerator';

export const findById = (cityId) => {
  return loadEntityById(cityId, ENTITY_TYPE_LOCATION_CITY);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_LOCATION_CITY], ['name', 'description', 'x_opencti_aliases'], args);
};

export const country = (cityId) => {
  return loadWithConnectedRelations(
    `match $to isa ${ENTITY_TYPE_LOCATION_COUNTRY}; 
    $rel(${RELATION_LOCATED_AT}_from:$from, ${RELATION_LOCATED_AT}_to:$to) isa ${RELATION_LOCATED_AT};
    $from has internal_id "${escapeString(cityId)}"; 
    get; offset 0; limit 1;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => (data ? data.node : undefined));
};

export const addCity = async (user, city) => {
  const created = await createEntity(user, city, ENTITY_TYPE_LOCATION_CITY);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
