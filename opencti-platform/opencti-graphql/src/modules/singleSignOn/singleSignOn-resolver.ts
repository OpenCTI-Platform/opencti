import type { Resolvers } from '../../generated/graphql';
import { runSingleSignOnRunMigration } from './singleSignOn-domain';

const singleSignOnResolver: Resolvers = {
  Mutation: {
    singleSignOnRunMigration: (_, { input }, context) => {
      return runSingleSignOnRunMigration(context, context.user, input);
    },
  },
};

export default singleSignOnResolver;
