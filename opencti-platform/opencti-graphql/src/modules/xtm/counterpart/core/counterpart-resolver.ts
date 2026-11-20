import type { Resolvers } from '../../../../generated/graphql';
import { type CounterpartKind, findXtmConnections, findXtmCounterparts } from './counterpart-domain';

const counterpartResolvers: Resolvers = {
  Query: {
    xtmConnections: (_, __, context) => findXtmConnections(context, context.user),
    xtmCounterparts: (_, { kind, keys }, context) => findXtmCounterparts(context, context.user, `${kind}` as CounterpartKind, keys),
  },
};

export default counterpartResolvers;
