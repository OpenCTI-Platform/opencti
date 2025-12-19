import type { Resolvers } from '../../generated/graphql';
import { findSingleSignOnById, findSingleSignOnPaginated, addSingleSignOn, fieldPatchSingleSignOn, deleteSingleSignOn, getConfigurationKeyList, getStrategyAttributes } from './SingleSignOn-domain';

const singleSignOnResolver: Resolvers = {
  Query: {
    singleSignOn: (_, { id }, context) => findSingleSignOnById(context, context.user, id),
    singleSignOns: (_, args, context) => findSingleSignOnPaginated(context, context.user, args),
    // singleSignOnAttributes: (_, { strategy }, context) => getStrategyAttributes(strategy),
  },
  SingleSignOn: {
    // used to have all mandatory fields for strategy
    mandatoryFields:  (singleSignOn) => getConfigurationKeyList(singleSignOn.strategy),
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