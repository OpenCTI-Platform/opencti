import { assoc, pipe, isNil } from 'ramda';
import { createEntity, batchListThroughGetTo } from '../database/middleware';
import { listEntities, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_INTRUSION_SET } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT, ENTITY_TYPE_LOCATION } from '../schema/general';
import { RELATION_ORIGINATES_FROM } from '../schema/stixCoreRelationship';
import { FROM_START, UNTIL_END } from '../utils/format';

export const findById = (context, user, intrusionSetId) => {
  return storeLoadById(context, user, intrusionSetId, ENTITY_TYPE_INTRUSION_SET);
};

export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_INTRUSION_SET], args);
};

export const addIntrusionSet = async (context, user, intrusionSet) => {
  const intrusionSetToCreate = pipe(
    assoc('first_seen', isNil(intrusionSet.first_seen) ? new Date(FROM_START) : intrusionSet.first_seen),
    assoc('last_seen', isNil(intrusionSet.last_seen) ? new Date(UNTIL_END) : intrusionSet.last_seen)
  )(intrusionSet);
  const created = await createEntity(context, user, intrusionSetToCreate, ENTITY_TYPE_INTRUSION_SET);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const batchLocations = (context, user, intrusionSetIds) => {
  return batchListThroughGetTo(context, user, intrusionSetIds, RELATION_ORIGINATES_FROM, ENTITY_TYPE_LOCATION);
};
