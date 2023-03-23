import type { AuthContext, AuthUser } from '../../../types/user';
import { createEntity } from '../../../database/middleware';
import type { EntityOptions } from '../../../database/middleware-loader';
import { internalLoadById, listEntitiesPaginated, storeLoadById } from '../../../database/middleware-loader';
import { BUS_TOPICS } from '../../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey } from '../../../schema/general';
import { notify } from '../../../database/redis';
import { now } from '../../../utils/format';
import { userAddIndividual } from '../../../domain/user';
import { isEmptyField } from '../../../database/utils';
import type { BasicStoreEntityFeedback } from './feedback-types';
import { ENTITY_TYPE_CONTAINER_FEEDBACK } from './feedback-types';
import type { DomainFindById } from '../../../domain/domainTypes';
import type { FeedbackAddInput } from '../../../generated/graphql';
import { isStixId } from '../../../schema/schemaUtils';
import { RELATION_OBJECT } from '../../../schema/stixMetaRelationship';

export const findById: DomainFindById<BasicStoreEntityFeedback> = (context: AuthContext, user: AuthUser, caseId: string) => {
  return storeLoadById(context, user, caseId, ENTITY_TYPE_CONTAINER_FEEDBACK);
};

export const findAll = (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityFeedback>) => {
  return listEntitiesPaginated<BasicStoreEntityFeedback>(context, user, [ENTITY_TYPE_CONTAINER_FEEDBACK], opts);
};

export const addFeedback = async (context: AuthContext, user: AuthUser, feedbackAdd: FeedbackAddInput) => {
  let caseToCreate = feedbackAdd.created ? feedbackAdd : { ...feedbackAdd, created: now() };
  if (isEmptyField(feedbackAdd.createdBy)) {
    let individualId = user.individual_id;
    if (individualId === undefined) {
      const individual = await userAddIndividual(context, user);
      individualId = individual.id;
    }
    caseToCreate = { ...caseToCreate, createdBy: individualId };
  }
  const created = await createEntity(context, user, caseToCreate, ENTITY_TYPE_CONTAINER_FEEDBACK);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const feedbackContainsStixObjectOrStixRelationship = async (context: AuthContext, user: AuthUser, feedbackId: string, thingId: string) => {
  const resolvedThingId = isStixId(thingId) ? (await internalLoadById(context, user, thingId)).internal_id : thingId;
  const args = {
    filters: [
      { key: 'internal_id', values: [feedbackId] },
      { key: buildRefRelationKey(RELATION_OBJECT), values: [resolvedThingId] },
    ],
  };
  const feedbackFound = await findAll(context, user, args);
  return feedbackFound.edges.length > 0;
};
