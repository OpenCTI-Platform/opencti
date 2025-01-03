import type { Resolvers } from '../../generated/graphql';
import { addRequestAccess, rejectRequestAccess, validateRequestAccess } from './requestAccess-domain';

const requestAccessResolvers: Resolvers = {
  Mutation: {
    requestAccessAdd: (_, { input }, context) => {
      return addRequestAccess(context, context.user, input);
    },
    requestAccessValidate: (_, { id }, context) => {
      return validateRequestAccess(context, context.user, id);
    },
    requestAccessReject: (_, { id }, context) => {
      return rejectRequestAccess(context, context.user, id);
    }
  }
};

export default requestAccessResolvers;
