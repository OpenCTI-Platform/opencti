import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../../domain/stixDomainObject';
import type { Resolvers } from '../../generated/graphql';
import {
  addFinancialAccount,
  addFinancialAsset,
  findAllFinancialAccounts,
  findAllFinancialAssets,
  findFinancialAccountById,
  findFinancialAssetById,
  updateFinancialAccount,
  updateFinancialAsset,
} from './financialData-domain';

export const financialAccountResolvers: Resolvers = {
  Query: {
    financialAccount: (_, { id }, context) => findFinancialAccountById(context, context.user, id),
    financialAccounts: (_, args, context) => findAllFinancialAccounts(context, context.user, args),
  },
  Mutation: {
    financialAccountAdd: (_, { input }, context) => addFinancialAccount(context, context.user, input),
    financialAccountUpdate: (_, { input }, context) => updateFinancialAccount(context.user, input),
    financialAccountDelete: (_, { id }, context) => stixDomainObjectDelete(context, context.user, id),
    financialAccountFieldPatch: (_, { id, input, commitMessage, references }, context) => {
      return stixDomainObjectEditField(
        context,
        context.user,
        id,
        input,
        {
          commitMessage,
          references
        });
    },
    financialAccountContextPatch: (_, { id, input }, context) => stixDomainObjectEditContext(context, context.user, id, input),
    financialAccountContextClean: (_, { id }, context) => stixDomainObjectCleanContext(context, context.user, id),
    financialAccountRelationAdd: (_, { id, input }, context) => stixDomainObjectAddRelation(context, context.user, id, input),
    financialAccountRelationDelete: (_, { id, toId, relationship_type }, context) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationship_type),
  },
};

export const financialAssetResolvers: Resolvers = {
  Query: {
    financialAsset: (_, { id }, context) => findFinancialAssetById(context, context.user, id),
    financialAssets: (_, args, context) => findAllFinancialAssets(context, context.user, args),
  },
  Mutation: {
    financialAssetAdd: (_, { input }, context) => addFinancialAsset(context, context.user, input),
    financialAssetUpdate: (_, { input }, context) => updateFinancialAsset(context.user, input),
    financialAssetDelete: (_, { id }, context) => stixDomainObjectDelete(context, context.user, id),
    financialAssetContextPatch: (_, { id, input }, context) => stixDomainObjectEditContext(context, context.user, id, input),
    financialAssetContextClean: (_, { id }, context) => stixDomainObjectCleanContext(context, context.user, id),
    financialAssetRelationAdd: (_, { id, input }, context) => stixDomainObjectAddRelation(context, context.user, id, input),
    financialAssetRelationDelete: (_, { id, toId, relationship_type }, context) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationship_type),
  },
};
