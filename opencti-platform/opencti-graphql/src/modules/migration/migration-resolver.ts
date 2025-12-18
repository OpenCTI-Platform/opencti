import type { Resolvers } from '../../generated/graphql';
import { runMigration } from './migration-domain';

const migrationResolvers: Resolvers = {
  Mutation: {
    runMigration: (_, { migrationName }, context) => runMigration(context, context.user, migrationName),
  },
};

export default migrationResolvers;
