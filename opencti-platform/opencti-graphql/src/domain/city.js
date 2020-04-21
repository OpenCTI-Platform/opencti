import {
  createEntity,
  escapeString,
  listEntities,
  loadEntityById,
  loadEntityByStixId,
  loadWithConnectedRelations,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { TYPE_STIX_DOMAIN_ENTITY } from '../database/utils';

export const findById = (cityId) => {
  if (cityId.match(/[a-z-]+--[\w-]{36}/g)) {
    return loadEntityByStixId(cityId, 'City');
  }
  return loadEntityById(cityId, 'City');
};
export const findAll = (args) => {
  return listEntities(['City'], ['name', 'alias'], args);
};
export const country = (cityId) => {
  return loadWithConnectedRelations(
    `match $to isa Country; $rel(localized:$from, location:$to) isa localization;
   $from has internal_id_key "${escapeString(cityId)}"; get; offset 0; limit 1;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => (data ? data.node : undefined));
};

export const addCity = async (user, city) => {
  const created = await createEntity(user, city, 'City', {
    modelType: TYPE_STIX_DOMAIN_ENTITY,
    stixIdType: 'identity',
  });
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
