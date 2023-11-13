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
  findAllFinancialAccounts,
  findFinancialAccountById,
} from './financialData-domain';

export const financialAccountResolvers: Resolvers = {
  Query: {
    financialAccount: (_, { id }, context) => findFinancialAccountById(context, context.user, id),
    financialAccounts: (_, args, context) => findAllFinancialAccounts(context, context.user, args),
  },
  Mutation: {
    financialAccountAdd: (_, { input }, context) => addFinancialAccount(context, context.user, input),
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
        }
      );
    },
    financialAccountContextPatch: (_, { id, input }, context) => stixDomainObjectEditContext(context, context.user, id, input),
    financialAccountContextClean: (_, { id }, context) => stixDomainObjectCleanContext(context, context.user, id),
    financialAccountRelationAdd: (_, { id, input }, context) => stixDomainObjectAddRelation(context, context.user, id, input),
    financialAccountRelationDelete: (_, { id, toId, relationship_type }, context) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationship_type),
  },
};
