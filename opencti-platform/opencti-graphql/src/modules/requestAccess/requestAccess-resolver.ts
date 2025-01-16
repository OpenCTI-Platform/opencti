import type { Resolvers } from '../../generated/graphql';
import { addRequestAccess, approveRequestAccess, declineRequestAccess } from './requestAccess-domain';

const requestAccessResolvers: Resolvers = {
  Mutation: {
    requestAccessAdd: (_, { input }, context) => {
      return addRequestAccess(context, context.user, input);
    },
    requestAccessApprove: (_, { id }, context) => {
      return approveRequestAccess(context, context.user, id);
    },
    requestAccessDecline: (_, { id }, context) => {
      return declineRequestAccess(context, context.user, id);
    }
  }
};

export default requestAccessResolvers;
