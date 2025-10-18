import type { Resolvers } from '../../generated/graphql';
import { patchMetric } from './metrics-domain';

const metricsResolver: Resolvers = {
  Mutation: {
    metricPatch: (_, { id, input }, context) => patchMetric(context, context.user, id, input),
  },
};

export default metricsResolver;
