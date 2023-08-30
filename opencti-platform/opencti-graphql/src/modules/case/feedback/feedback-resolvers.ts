import type { Resolvers } from '../../../generated/graphql';
import { buildRefRelationKey } from '../../../schema/general';
import { RELATION_CREATED_BY, RELATION_OBJECT_ASSIGNEE, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../../../schema/stixRefRelationship';
import { stixDomainObjectDelete } from '../../../domain/stixDomainObject';
import { addFeedback, feedbackContainsStixObjectOrStixRelationship, findAll, findById } from './feedback-domain';

const feedbackResolvers: Resolvers = {
  Query: {
    feedback: (_, { id }, context) => findById(context, context.user, id),
    feedbacks: (_, args, context) => findAll(context, context.user, args),
    feedbackContainsStixObjectOrStixRelationship: (_, args, context) => {
      return feedbackContainsStixObjectOrStixRelationship(context, context.user, args.id, args.stixObjectOrStixRelationshipId);
    },
  },
  FeedbacksFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    objectAssignee: buildRefRelationKey(RELATION_OBJECT_ASSIGNEE),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    objectLabel: buildRefRelationKey(RELATION_OBJECT_LABEL),
    creator: 'creator_id',
  },
  FeedbacksOrdering: {
    creator: 'creator_id',
  },
  Mutation: {
    feedbackAdd: (_, { input }, context) => {
      return addFeedback(context, context.user, input);
    },
    feedbackDelete: (_, { id }, context) => {
      return stixDomainObjectDelete(context, context.user, id);
    },
  }
};

export default feedbackResolvers;
