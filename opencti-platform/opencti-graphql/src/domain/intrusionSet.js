import { assoc, pipe } from 'ramda';
import { createEntity, loadEntityById, now } from '../database/grakn';
import { elPaginate } from '../database/elasticSearch';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';

export const findById = intrusionSetId => {
  return loadEntityById(intrusionSetId);
};
export const findAll = args => {
  return elPaginate('stix_domain_entities', assoc('type', 'intrusion-set', args));
};

export const addIntrusionSet = async (user, intrusionSet) => {
  const currentDate = now();
  const intrusionSetToCreate = pipe(
    assoc('first_seen', intrusionSet.first_seen ? intrusionSet.first_seen : currentDate),
    assoc('last_seen', intrusionSet.first_seen ? intrusionSet.first_seen : currentDate)
  )(intrusionSet);
  const created = await createEntity(intrusionSetToCreate, 'Intrusion-Set');
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
