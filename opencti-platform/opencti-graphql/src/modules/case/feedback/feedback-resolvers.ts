import type { Resolvers } from '../../../generated/graphql';
import { stixDomainObjectDelete } from '../../../domain/stixDomainObject';
import { addFeedback, feedbackContainsStixObjectOrStixRelationship, feedbackEditAuthorizedMembers, findAll, findById } from './feedback-domain';
import { getAuthorizedMembers } from '../../../utils/authorizedMembers';
import { getUserAccessRight } from '../../../utils/access';

const feedbackResolvers: Resolvers = {
  Query: {
    feedback: (_, { id }, context) => findById(context, context.user, id),
    feedbacks: (_, args, context) => findAll(context, context.user, args),
    feedbackContainsStixObjectOrStixRelationship: (_, args, context) => {
      return feedbackContainsStixObjectOrStixRelationship(context, context.user, args.id, args.stixObjectOrStixRelationshipId);
    },
  },
  Feedback: {
    authorized_members: (feedback, _, context) => getAuthorizedMembers(context, context.user, feedback),
    currentUserAccessRight: (feedback, _, context) => getUserAccessRight(context.user, feedback),
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
    feedbackEditAuthorizedMembers: (_, { id, input }, context) => {
      return feedbackEditAuthorizedMembers(context, context.user, id, input);
    },
  }
};

export default feedbackResolvers;
