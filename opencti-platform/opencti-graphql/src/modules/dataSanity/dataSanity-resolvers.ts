import type { Resolvers } from '../../generated/graphql';
import { listAllSanityFixes, setForceRun } from './dataSanity-domain';

const dataSanityResolvers: Resolvers = {
  Query: {
    dataSanityFixes: (_, __, context) => listAllSanityFixes(context),
  },
  Mutation: {
    dataSanityFixForceRun: (_, { fix_name }, context) => setForceRun(context, context.user, fix_name),
  },
};

export default dataSanityResolvers;
