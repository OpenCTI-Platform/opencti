import { assoc, pipe } from 'ramda';
import { createEntity, listEntities, loadEntityById, now } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_INTRUSION } from '../utils/idGenerator';

export const findById = (intrusionSetId) => {
  return loadEntityById(intrusionSetId, ENTITY_TYPE_INTRUSION);
};
export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_INTRUSION], ['name', 'alias'], args);
};

export const addIntrusionSet = async (user, intrusionSet) => {
  const currentDate = now();
  const intrusionSetToCreate = pipe(
    assoc('first_seen', intrusionSet.first_seen ? intrusionSet.first_seen : currentDate),
    assoc('last_seen', intrusionSet.last_seen ? intrusionSet.last_seen : currentDate)
  )(intrusionSet);
  const created = await createEntity(user, intrusionSetToCreate, ENTITY_TYPE_INTRUSION);
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
