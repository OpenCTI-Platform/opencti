import { assoc, isNil, pipe } from 'ramda';
import { createEntity } from '../database/middleware';
import { listEntities, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_THREAT_ACTOR_GROUP } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { FROM_START, UNTIL_END } from '../utils/format';

export const findById = (context, user, threatActorId) => {
  return storeLoadById(context, user, threatActorId, ENTITY_TYPE_THREAT_ACTOR_GROUP);
};

export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_THREAT_ACTOR_GROUP], args);
};

export const addThreatActorGroup = async (context, user, threatActorGroup) => {
  const threatActorGroupToCreate = pipe(
    assoc('first_seen', isNil(threatActorGroup.first_seen) ? new Date(FROM_START) : threatActorGroup.first_seen),
    assoc('last_seen', isNil(threatActorGroup.last_seen) ? new Date(UNTIL_END) : threatActorGroup.last_seen)
  )(threatActorGroup);
  const created = await createEntity(context, user, threatActorGroupToCreate, ENTITY_TYPE_THREAT_ACTOR_GROUP);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
