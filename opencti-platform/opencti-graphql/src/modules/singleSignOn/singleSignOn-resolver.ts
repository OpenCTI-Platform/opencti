import type { Resolvers } from '../../generated/graphql';
import {
  findSingleSignOnById,
  findSingleSignOnPaginated,
  addSingleSignOn,
  fieldPatchSingleSignOn,
  deleteSingleSignOn,
  runSingleSignOnRunMigration,
  getSingleSignOnSettings,
} from './singleSignOn-domain';

const singleSignOnResolver: Resolvers = {
  Query: {
    singleSignOn: (_, { id }, context) => findSingleSignOnById(context, context.user, id),
    singleSignOns: (_, args, context) => findSingleSignOnPaginated(context, context.user, args),
    singleSignOnSettings: () => getSingleSignOnSettings(),
  },
  Mutation: {
    singleSignOnAdd: (_, { input }, context) => {
      return addSingleSignOn(context, context.user, input);
    },
    singleSignOnFieldPatch: (_, { id, input }, context) => {
      return fieldPatchSingleSignOn(context, context.user, id, input);
    },
    singleSignOnDelete: (_, { id }, context) => {
      return deleteSingleSignOn(context, context.user, id);
    },
    singleSignOnRunMigration: (_, { input }, context) => {
      return runSingleSignOnRunMigration(context, context.user, input);
    },
  },
};

export default singleSignOnResolver;
