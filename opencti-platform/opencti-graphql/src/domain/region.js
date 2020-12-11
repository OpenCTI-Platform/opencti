import { assoc } from 'ramda';
import { createEntity, listEntities, listThroughGetFroms, listThroughGetTos, loadById } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_LOCATION_COUNTRY, ENTITY_TYPE_LOCATION_REGION } from '../schema/stixDomainObject';
import { RELATION_LOCATED_AT } from '../schema/stixCoreRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';

export const findById = (regionId) => {
  return loadById(regionId, ENTITY_TYPE_LOCATION_REGION);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_LOCATION_REGION], args);
};

export const batchParentRegions = (regionIds) => {
  return listThroughGetTos(regionIds, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_REGION);
};

export const batchSubRegions = (regionIds) => {
  return listThroughGetFroms(regionIds, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_REGION);
};

export const batchCountries = (regionIds) => {
  return listThroughGetFroms(regionIds, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_COUNTRY);
};

export const batchIsSubRegion = async (regionIds) => {
  const batchRegions = await listThroughGetTos(regionIds, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_REGION);
  return batchRegions.map((b) => b.edges.length > 0);
};

export const addRegion = async (user, region) => {
  const created = await createEntity(
    user,
    assoc('x_opencti_location_type', ENTITY_TYPE_LOCATION_REGION, region),
    ENTITY_TYPE_LOCATION_REGION
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
