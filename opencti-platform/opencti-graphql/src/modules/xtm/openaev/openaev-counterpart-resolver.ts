import type { Resolvers } from '../../../generated/graphql';
import { type CounterpartKind, findXtmConnections, findXtmCounterparts } from './openaev-counterpart-domain';

const openAevCounterpartResolvers: Resolvers = {
  Query: {
    xtmConnections: (_, __, context) => findXtmConnections(context, context.user),
    xtmCounterparts: (_, { kind, keys }, context) => findXtmCounterparts(context, context.user, `${kind}` as CounterpartKind, keys),
  },
};

export default openAevCounterpartResolvers;
