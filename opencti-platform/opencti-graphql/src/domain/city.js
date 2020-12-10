import { assoc } from 'ramda';
import * as R from 'ramda';
import { createEntity, listEntities, listThroughGetTos, loadById } from '../database/grakn';
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

export const batchCountry = async (cityIds) => {
  const batchCreators = await listThroughGetTos(cityIds, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_COUNTRY);
  return batchCreators.map((b) => (b.edges.length > 0 ? R.head(b.edges).node : null));
};

export const addCity = async (user, city) => {
  const created = await createEntity(
    user,
    assoc('x_opencti_location_type', ENTITY_TYPE_LOCATION_CITY, city),
    ENTITY_TYPE_LOCATION_CITY
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};