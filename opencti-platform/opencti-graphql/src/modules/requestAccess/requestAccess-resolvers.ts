import type { Resolvers } from '../../generated/graphql';
import { findById, findAll, addRequestAccess, validateRequestAccess } from './requestAccess-domain';

const requestAccessResolvers: Resolvers = {
  Query: {
    requestAccess: (_, { id }, context) => findById(context, context.user, id),
    requestAccesses: (_, args, context) => findAll(context, context.user, args),
  },
  Mutation: {
    requestAccessAdd: (_, { input }, context) => {
      return addRequestAccess(context, context.user, input);
    },
    requestAccessValidate: (_, { id }, context) => {
      return validateRequestAccess(context, context.user, id);
    }
  }
};

export default requestAccessResolvers;
