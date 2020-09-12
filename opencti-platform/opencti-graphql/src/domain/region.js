import { assoc, isNil, map } from 'ramda';
import {
  createEntity,
  escapeString,
  getSingleValueNumber,
  listEntities,
  listFromEntitiesThroughRelation,
  listToEntitiesThroughRelation,
  loadById,
  updateAttribute,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_LOCATION_COUNTRY, ENTITY_TYPE_LOCATION_REGION } from '../schema/stixDomainObject';
import { RELATION_LOCATED_AT } from '../schema/stixCoreRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';

export const findById = (regionId) => {
  return loadById(regionId, ENTITY_TYPE_LOCATION_REGION);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_LOCATION_REGION], ['name', 'description', 'x_opencti_aliases'], args);
};

export const parentRegions = (regionId) => {
  return listToEntitiesThroughRelation(regionId, null, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_REGION);
};

export const subRegions = (regionId) => {
  return listFromEntitiesThroughRelation(regionId, null, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_REGION);
};

export const countries = (regionId) => {
  return listFromEntitiesThroughRelation(regionId, null, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_COUNTRY, true);
};

export const isSubRegion = async (regionId) => {
  const numberOfParents = await getSingleValueNumber(
    `match $parent isa Region; 
    $rel(${RELATION_LOCATED_AT}_from:$subregion, ${RELATION_LOCATED_AT}_to:$parent) isa ${RELATION_LOCATED_AT}; 
    $subregion has internal_id "${escapeString(regionId)}"; 
    get; count;`
  );
  return numberOfParents > 0;
};

export const addRegion = async (user, region) => {
  const created = await createEntity(
    user,
    assoc('x_opencti_location_type', ENTITY_TYPE_LOCATION_REGION, region),
    ENTITY_TYPE_LOCATION_REGION
  );
  if (region.update === true) {
    const fieldsToUpdate = ['description', 'longitude', 'latitude'];
    await Promise.all(
      map((field) => {
        if (!isNil(region[field])) {
          return updateAttribute(user, created.id, created.entity_type, { key: field, value: [region[field]] });
        }
        return true;
      }, fieldsToUpdate)
    );
  }
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
