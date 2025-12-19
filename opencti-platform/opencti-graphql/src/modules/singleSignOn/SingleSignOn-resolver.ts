import type { Resolvers } from '../../generated/graphql';
import { findSingleSignOnById, findSingleSignOnPaginated, addSingleSignOn, fieldPatchSingleSignOn, deleteSingleSignOn } from './SingleSignOn-domain';

// resolve mandatory key list depending of strategy => ex: SAML_CONFIGURATION_KEY_LIST ( types.ts )

const singleSignOnResolver: Resolvers = {
  Query: {
    singleSignOn: (_, { id }, context) => findSingleSignOnById(context, context.user, id),
    singleSignOns: (_, args, context) => findSingleSignOnPaginated(context, context.user, args),
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
  },
};

export default singleSignOnResolver;