import type { Resolvers } from '../../generated/graphql';
import { addRequestAccess, configureRequestAccess } from './requestAccess-domain';

const requestAccessResolvers: Resolvers = {
  Mutation: {
    requestAccessAdd: (_, { input }, context) => {
      return addRequestAccess(context, context.user, input);
    },
    requestAccessConfigure: (_, { input }, context) => {
      return configureRequestAccess(context, context.user, input);
    },
  }
};

export default requestAccessResolvers;
