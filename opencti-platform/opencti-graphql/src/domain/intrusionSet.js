import { assoc, pipe } from 'ramda';
import { createEntity, listEntities, loadEntityById, loadEntityByStixId, now } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';

export const findById = (intrusionSetId) => {
  if (intrusionSetId.match(/[a-z-]+--[\w-]{36}/g)) {
    return loadEntityByStixId(intrusionSetId, 'Intrusion-Set');
  }
  return loadEntityById(intrusionSetId, 'Intrusion-Set');
};
export const findAll = (args) => {
  return listEntities(['Intrusion-Set'], ['name', 'alias'], args);
};

export const addIntrusionSet = async (user, intrusionSet) => {
  const currentDate = now();
  const intrusionSetToCreate = pipe(
    assoc('first_seen', intrusionSet.first_seen ? intrusionSet.first_seen : currentDate),
    assoc('last_seen', intrusionSet.last_seen ? intrusionSet.last_seen : currentDate)
  )(intrusionSet);
  const created = await createEntity(user, intrusionSetToCreate, 'Intrusion-Set');
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
