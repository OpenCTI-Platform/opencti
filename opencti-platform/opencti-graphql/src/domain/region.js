import { createEntity, escapeString, findWithConnectedRelations, getSingleValueNumber, listEntities, loadEntityById, loadEntityByStixId } from "../database/grakn";
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { buildPagination, TYPE_STIX_DOMAIN_ENTITY } from "../database/utils";

export const findById = (regionId) => {
  if (regionId.match(/[a-z-]+--[\w-]{36}/g)) {
    return loadEntityByStixId(regionId, 'Region');
  }
  return loadEntityById(regionId, 'Region');
};
export const findAll = (args) => {
  return listEntities(['Region'], ['name', 'alias'], args);
};
export const parentRegions = (regionId) => {
  return findWithConnectedRelations(
    `match $to isa Region; $rel(localized:$from, location:$to) isa localization;
     $from has internal_id_key "${escapeString(regionId)}"; get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
export const subRegions = (regionId) => {
  return findWithConnectedRelations(
    `match $to isa Region; $rel(location:$from, localized:$to) isa localization;
     $from has internal_id_key "${escapeString(regionId)}"; get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const isSubRegion = async (regionId, args) => {
  const numberOfParents = await getSingleValueNumber(
    `match $parent isa Region; 
    $rel(location:$parent, localized:$subregion) isa localization; 
    $subregion has internal_id_key "${escapeString(regionId)}"; get; count;`,
    args
  );
  return numberOfParents > 0;
};
export const addRegion = async (user, region) => {
  const created = await createEntity(user, region, 'Region', {
    modelType: TYPE_STIX_DOMAIN_ENTITY,
    stixIdType: 'identity',
  });
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
