import type { Resolvers } from '../../../../generated/graphql';
import { findXtmConnections, findXtmCounterpartsByIds } from './counterpart-domain';

const counterpartResolvers: Resolvers = {
  Query: {
    xtmConnections: (_, __, context) => findXtmConnections(context, context.user),
    xtmCounterpartsOf: (_, { ids }, context) => findXtmCounterpartsByIds(context, context.user, ids) as any,
  },
};

export default counterpartResolvers;
