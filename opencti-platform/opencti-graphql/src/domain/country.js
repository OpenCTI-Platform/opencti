import {
  createEntity,
  escapeString,
  listEntities,
  loadEntityById,
  loadWithConnectedRelations,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_COUNTRY, ENTITY_TYPE_REGION } from '../utils/idGenerator';

export const findById = (countryId) => {
  return loadEntityById(countryId, 'Country');
};
export const findAll = (args) => {
  return listEntities(['Country'], ['name', 'alias'], args);
};
export const region = (countryId) => {
  return loadWithConnectedRelations(
    `match $to isa ${ENTITY_TYPE_REGION}; $rel(localized:$from, location:$to) isa localization;
   $from has internal_id "${escapeString(countryId)}"; get; offset 0; limit 1;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => (data ? data.node : undefined));
};

export const addCountry = async (user, country) => {
  const created = await createEntity(user, country, ENTITY_TYPE_COUNTRY);
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
