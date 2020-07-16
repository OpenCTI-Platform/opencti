import {
  createEntity,
  escapeString,
  listEntities,
  loadEntityById,
  loadWithConnectedRelations,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_CITY, ENTITY_TYPE_COUNTRY } from '../utils/idGenerator';

export const findById = (cityId) => {
  return loadEntityById(cityId, ENTITY_TYPE_CITY);
};
export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_CITY], ['name', 'alias'], args);
};
export const country = (cityId) => {
  return loadWithConnectedRelations(
    `match $to isa ${ENTITY_TYPE_COUNTRY}; $rel(localized:$from, location:$to) isa localization;
   $from has internal_id "${escapeString(cityId)}"; get; offset 0; limit 1;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => (data ? data.node : undefined));
};

export const addCity = async (user, city) => {
  const created = await createEntity(user, city, ENTITY_TYPE_CITY);
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
