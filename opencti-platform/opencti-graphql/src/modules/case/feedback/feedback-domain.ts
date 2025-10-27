import type { AuthContext, AuthUser } from '../../../types/user';
import { createEntity } from '../../../database/middleware';
import type { EntityOptions } from '../../../database/middleware-loader';
import { internalLoadById, pageEntitiesConnection, storeLoadById } from '../../../database/middleware-loader';
import { BUS_TOPICS } from '../../../config/conf';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey } from '../../../schema/general';
import { notify } from '../../../database/redis';
import { now } from '../../../utils/format';
import { resolveUserIndividual } from '../../../domain/user';
import { isEmptyField } from '../../../database/utils';
import type { DomainFindById } from '../../../domain/domainTypes';
import type { FeedbackAddInput, MemberAccessInput } from '../../../generated/graphql';
import { isStixId } from '../../../schema/schemaUtils';
import { RELATION_OBJECT } from '../../../schema/stixRefRelationship';
import { FilterMode } from '../../../generated/graphql';
import { editAuthorizedMembers } from '../../../utils/authorizedMembers';
import { type BasicStoreEntityFeedback, ENTITY_TYPE_CONTAINER_FEEDBACK } from './feedback-types';

export const findById: DomainFindById<BasicStoreEntityFeedback> = (context: AuthContext, user: AuthUser, caseId: string) => {
  return storeLoadById(context, user, caseId, ENTITY_TYPE_CONTAINER_FEEDBACK);
};

export const findFeedbackPaginated = (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityFeedback>) => {
  return pageEntitiesConnection<BasicStoreEntityFeedback>(context, user, [ENTITY_TYPE_CONTAINER_FEEDBACK], opts);
};

export const addFeedback = async (context: AuthContext, user: AuthUser, feedbackAdd: FeedbackAddInput) => {
  let caseToCreate = feedbackAdd.created ? feedbackAdd : { ...feedbackAdd, created: now() };
  if (isEmptyField(feedbackAdd.createdBy)) {
    const individualId = await resolveUserIndividual(context, user);
    caseToCreate = { ...caseToCreate, createdBy: individualId };
  }
  const created = await createEntity(context, user, caseToCreate, ENTITY_TYPE_CONTAINER_FEEDBACK);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const feedbackContainsStixObjectOrStixRelationship = async (context: AuthContext, user: AuthUser, feedbackId: string, thingId: string) => {
  const resolvedThingId = isStixId(thingId) ? (await internalLoadById(context, user, thingId)).internal_id : thingId;
  const args = {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['internal_id'], values: [feedbackId] },
        { key: [buildRefRelationKey(RELATION_OBJECT)], values: [resolvedThingId] },
      ],
      filterGroups: [],
    },
  };
  const feedbackFound = await findFeedbackPaginated(context, user, args);
  return feedbackFound.edges.length > 0;
};

export const feedbackEditAuthorizedMembers = async (
  context: AuthContext,
  user: AuthUser,
  entityId: string,
  input: MemberAccessInput[] | undefined | null
) => {
  const args = {
    entityId,
    input,
    requiredCapabilities: ['KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS'],
    entityType: ENTITY_TYPE_CONTAINER_FEEDBACK,
    busTopicKey: ABSTRACT_STIX_CORE_OBJECT,
  };
  // @ts-expect-error TODO improve busTopicKey types to avoid this
  return editAuthorizedMembers(context, user, args);
};
