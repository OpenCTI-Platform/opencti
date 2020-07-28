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
  ENTITY_TYPE_LOCATION_POSITION,
  ENTITY_TYPE_LOCATION_CITY,
  RELATION_LOCATED_AT,
} from '../utils/idGenerator';

export const findById = (positionId) => {
  return loadEntityById(positionId, ENTITY_TYPE_LOCATION_POSITION);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_LOCATION_POSITION], ['name', 'description', 'x_opencti_aliases'], args);
};

export const city = (positionId) => {
  return loadWithConnectedRelations(
    `match $to isa ${ENTITY_TYPE_LOCATION_CITY}; 
    $rel(${RELATION_LOCATED_AT}_from:$from, ${RELATION_LOCATED_AT}_to:$to) isa ${RELATION_LOCATED_AT};
    $from has internal_id "${escapeString(positionId)}"; get; offset 0; limit 1;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => (data ? data.node : undefined));
};

export const addPosition = async (user, position) => {
  const created = await createEntity(user, position, ENTITY_TYPE_LOCATION_POSITION);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
