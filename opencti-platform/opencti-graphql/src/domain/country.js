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

export const findById = (countryId) => {
  if (countryId.match(/[a-z-]+--[\w-]{36}/g)) {
    return loadEntityByStixId(countryId, 'Country');
  }
  return loadEntityById(countryId, 'Country');
};
export const findAll = (args) => {
  return listEntities(['Country'], ['name', 'alias'], args);
};
export const region = (countryId) => {
  return loadWithConnectedRelations(
    `match $to isa Region; $rel(localized:$from, location:$to) isa localization;
   $from has internal_id_key "${escapeString(countryId)}"; get; offset 0; limit 1;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => (data ? data.node : undefined));
};

export const addCountry = async (user, country) => {
  const created = await createEntity(user, country, 'Country', {
    modelType: TYPE_STIX_DOMAIN_ENTITY,
    stixIdType: 'identity',
  });
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
