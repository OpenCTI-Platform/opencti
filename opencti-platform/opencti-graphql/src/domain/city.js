import {
  createEntity,
  escapeString,
  listEntities,
  loadEntityById,
  loadEntityByStixId,
  loadWithConnectedRelations,
  TYPE_STIX_DOMAIN_ENTITY
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';

export const findById = cityId => {
  if (cityId.match(/[a-z-]+--[\w-]{36}/g)) {
    return loadEntityByStixId(cityId);
  }
  return loadEntityById(cityId);
};
export const findAll = args => {
  return listEntities(['City'], ['name', 'alias'], args);
};
export const country = cityId => {
  return loadWithConnectedRelations(
    `match $to isa Country; $rel(localized:$from, location:$to) isa localization;
   $from has internal_id_key "${escapeString(cityId)}"; get; offset 0; limit 1;`,
    'to',
    'rel'
  );
};

export const addCity = async (user, city) => {
  const created = await createEntity(city, 'City', { modelType: TYPE_STIX_DOMAIN_ENTITY, stixIdType: 'identity' });
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
