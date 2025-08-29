import type { Resolvers } from '../../../generated/graphql';
import { checkXTMHubConnectivity } from '../../../domain/xtm-hub';

const xtmHubResolvers: Resolvers = {
  Mutation: {
    checkXTMHubConnectivity: (_, __, context) => checkXTMHubConnectivity(context, context.user),
  },
};

export default xtmHubResolvers;
