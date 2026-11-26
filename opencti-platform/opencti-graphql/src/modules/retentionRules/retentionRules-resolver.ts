import { checkRetentionRule, createRetentionRule, deleteRetentionRule, findRetentionRulePaginated, findById, retentionRuleEditField } from './retentionRules-domain';
import type { Resolvers } from '../../generated/graphql';
import { editMutations } from '../../graphql/edit-mutations';
import { isNotEmptyField } from '../../database/utils';

const retentionRulesResolver: Resolvers = {
  Query: {
    retentionRule: (_: any, { id }: any, context: any) => findById(context, context.user, id),
    retentionRules: (_: any, args: any, context: any) => findRetentionRulePaginated(context, context.user, args),
  },
  Mutation: {
    retentionRuleAdd: (_: any, { input }: any, context: any) => createRetentionRule(context, context.user, input),
    retentionRuleCheck: (_: any, { input }: any, context: any) => checkRetentionRule(context, input),
    retentionRuleEdit: (_, { id }, context) => editMutations<'RetentionRuleEditMutations'>({
      delete: () => deleteRetentionRule(context, context.user, id),
      fieldPatch: ({ input }) => retentionRuleEditField(context, context.user, id, input.filter(isNotEmptyField)),
    }),
  },
};

export default retentionRulesResolver;
