import { checkRetentionRule, createRetentionRule, deleteRetentionRule, findRetentionRulePaginated, findById, retentionRuleEditField } from './retentionRules-domain';
import type { EditInput } from '../../generated/graphql';

const retentionRulesResolver = {
  Query: {
    retentionRule: (_: any, { id }: any, context: any) => findById(context, context.user, id),
    retentionRules: (_: any, args: any, context: any) => findRetentionRulePaginated(context, context.user, args),
  },
  Mutation: {
    retentionRuleAdd: (_: any, { input }: any, context: any) => createRetentionRule(context, context.user, input),
    retentionRuleCheck: (_: any, { input }: any, context: any) => checkRetentionRule(context, input),
    retentionRuleEdit: (_: any, { id }: any, context: any) => ({
      delete: () => deleteRetentionRule(context, context.user, id),
      fieldPatch: ({ input }: { input: EditInput[] }) => retentionRuleEditField(context, context.user, id, input),
    }),
  },
};

export default retentionRulesResolver;
