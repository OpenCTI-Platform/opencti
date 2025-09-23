import { assoc, isNil, pipe } from 'ramda';
import type { DomainFindById } from '../../domain/domainTypes';
import type { AuthContext, AuthUser } from '../../types/user';
import { type EntityOptions, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { createEntity } from '../../database/middleware';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { type BasicStoreEntityThreatActorIndividual, ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from './threatActorIndividual-types';
import type { ThreatActorIndividualAddInput } from '../../generated/graphql';
import { FROM_START, UNTIL_END } from '../../utils/format';

export const findById: DomainFindById<BasicStoreEntityThreatActorIndividual> = (context: AuthContext, user: AuthUser, threatActorIndividualId: string) => {
  return storeLoadById<BasicStoreEntityThreatActorIndividual>(context, user, threatActorIndividualId, ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL);
};

export const findThreatActorIndividualPaginated = (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityThreatActorIndividual>) => {
  return pageEntitiesConnection<BasicStoreEntityThreatActorIndividual>(context, user, [ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL], opts);
};

export const addThreatActorIndividual = async (context: AuthContext, user: AuthUser, input: ThreatActorIndividualAddInput) => {
  const threatActor = pipe(
    assoc('first_seen', isNil(input.first_seen) ? new Date(FROM_START) : input.first_seen),
    assoc('last_seen', isNil(input.last_seen) ? new Date(UNTIL_END) : input.last_seen)
  )(input);
  const created = await createEntity(context, user, threatActor, ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
