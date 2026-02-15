import type { Resolvers } from '../../generated/graphql';
import {
  findSingleSignOnById,
  findSingleSignOnPaginated,
  addSingleSignOn,
  editSingleSignOn,
  deleteSingleSignOn,
  runSingleSignOnRunMigration,
  getSingleSignOnSettings,
  maskEncryptedConfigurationKeys,
} from './singleSignOn-domain';
import type { BasicStoreEntitySingleSignOn } from './singleSignOn-types';

const singleSignOnResolver: Resolvers = {
  Query: {
    singleSignOn: (_, { id }, context) => findSingleSignOnById(context, context.user, id),
    singleSignOns: (_, args, context) => findSingleSignOnPaginated(context, context.user, args),
    singleSignOnSettings: (_, __, ___) => getSingleSignOnSettings(),
  },
  SingleSignOn: {
    configuration: (singleSignOn) => maskEncryptedConfigurationKeys(singleSignOn as unknown as BasicStoreEntitySingleSignOn),
  },
  Mutation: {
    singleSignOnAdd: (_, { input }, context) => {
      return addSingleSignOn(context, context.user, input);
    },
    singleSignOnEdit: (_, { id, input }, context) => {
      return editSingleSignOn(context, context.user, id, input);
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
