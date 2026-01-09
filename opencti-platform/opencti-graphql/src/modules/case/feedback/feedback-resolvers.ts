import type { Resolvers } from '../../../generated/graphql';
import { addFeedback, feedbackContainsStixObjectOrStixRelationship, feedbackEditAuthorizedMembers, findFeedbackPaginated, findById } from './feedback-domain';
import { stixDomainObjectDelete } from '../../../domain/stixDomainObject';
import { ENTITY_TYPE_CONTAINER_FEEDBACK } from './feedback-types';

const feedbackResolvers: Resolvers = {
  Query: {
    feedback: (_, { id }, context) => findById(context, context.user, id),
    feedbacks: (_, args, context) => findFeedbackPaginated(context, context.user, args),
    feedbackContainsStixObjectOrStixRelationship: (_, args, context) => {
      return feedbackContainsStixObjectOrStixRelationship(context, context.user, args.id, args.stixObjectOrStixRelationshipId);
    },
  },
  FeedbacksOrdering: {
    creator: 'creator_id',
  },
  Mutation: {
    feedbackAdd: (_, { input }, context) => {
      return addFeedback(context, context.user, input);
    },
    feedbackDelete: (_, { id }, context) => {
      return stixDomainObjectDelete(context, context.user, id, ENTITY_TYPE_CONTAINER_FEEDBACK);
    },
    feedbackEditAuthorizedMembers: (_, { id, input }, context) => {
      return feedbackEditAuthorizedMembers(context, context.user, id, input);
    },
  },
};

export default feedbackResolvers;
