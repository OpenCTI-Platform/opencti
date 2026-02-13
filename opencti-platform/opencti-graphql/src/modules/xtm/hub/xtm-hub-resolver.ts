import type { Resolvers } from '../../../generated/graphql';
import { autoRegisterOpenCTI, checkXTMHubConnectivity, contactUsXtmHub } from '../../../domain/xtm-hub';

const xtmHubResolvers: Resolvers = {
  Mutation: {
    checkXTMHubConnectivity: (_, __, context) => checkXTMHubConnectivity(context, context.user),
    autoRegisterOpenCTI: (_, { input }, context) => autoRegisterOpenCTI(context, context.user, input),
    contactUsXtmHub: (_, { message }, context) => contactUsXtmHub(context, context.user, message),
  },
};

export default xtmHubResolvers;
