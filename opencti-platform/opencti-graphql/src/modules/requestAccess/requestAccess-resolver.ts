import type { Resolvers } from '../../generated/graphql';
import { addRequestAccess } from './requestAccess-domain';

const requestAccessResolvers: Resolvers = {
  Mutation: {
    requestAccessAdd: (_, { input }, context) => {
      return addRequestAccess(context, context.user, input);
    }
  }
};

export default requestAccessResolvers;
