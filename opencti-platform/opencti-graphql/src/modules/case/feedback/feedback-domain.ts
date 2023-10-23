import type { AuthContext, AuthUser } from '../../../types/user';
import { createEntity, patchAttribute } from '../../../database/middleware';
import type { EntityOptions } from '../../../database/middleware-loader';
import { internalLoadById, listEntitiesPaginated, storeLoadById } from '../../../database/middleware-loader';
import { BUS_TOPICS } from '../../../config/conf';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey } from '../../../schema/general';
import { notify } from '../../../database/redis';
import { now } from '../../../utils/format';
import { userAddIndividual } from '../../../domain/user';
import { isEmptyField } from '../../../database/utils';
import type { BasicStoreEntityFeedback } from './feedback-types';
import { ENTITY_TYPE_CONTAINER_FEEDBACK } from './feedback-types';
import type { DomainFindById } from '../../../domain/domainTypes';
import type { FeedbackAddInput, MemberAccessInput } from '../../../generated/graphql';
import { isStixId } from '../../../schema/schemaUtils';
import { RELATION_OBJECT } from '../../../schema/stixRefRelationship';
import { FilterMode } from '../../../generated/graphql';
import { isValidMemberAccessRight } from '../../../utils/access';
import { containsValidAdmin } from '../../../utils/authorizedMembers';
import { FunctionalError } from '../../../config/errors';

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
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['internal_id'], values: [feedbackId] },
        { key: [buildRefRelationKey(RELATION_OBJECT)], values: [resolvedThingId] },
      ],
      filterGroups: [],
    },
  };
  const feedbackFound = await findAll(context, user, args);
  return feedbackFound.edges.length > 0;
};

export const feedbackEditAuthorizedMembers = async (
  context: AuthContext,
  user: AuthUser,
  entityId: string,
  input: MemberAccessInput[] | undefined | null
) => {
  let authorized_members: { id: string, access_right: string }[] | null = null;

  if (input) {
    // validate input (validate access right) and remove duplicates
    const filteredInput = input.filter((value, index, array) => {
      return isValidMemberAccessRight(value.access_right) && array.findIndex((e) => e.id === value.id) === index;
    });

    const hasValidAdmin = await containsValidAdmin(
      context,
      filteredInput,
      ['KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS']
    );
    if (!hasValidAdmin) {
      throw FunctionalError('It should have at least one valid member with admin access');
    }

    authorized_members = filteredInput.map(({ id, access_right }) => ({ id, access_right }));
  }

  const patch = { authorized_members };
  const { element } = await patchAttribute(context, user, entityId, ENTITY_TYPE_CONTAINER_FEEDBACK, patch);
  return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_OBJECT].EDIT_TOPIC, element, user);
};
