import { checkRetentionRule, createRetentionRule, deleteRetentionRule, findAll, findById, retentionRuleEditField } from '../domain/retentionRule';

const retentionResolvers = {
  Query: {
    retentionRule: (_, { id }, context) => findById(context, context.user, id),
    retentionRules: (_, args, context) => findAll(context, context.user, args),
  },
  Mutation: {
    retentionRuleAdd: (_, { input }, context) => createRetentionRule(context, context.user, input),
    retentionRuleCheck: (_, { input }, context) => checkRetentionRule(context, input),
    retentionRuleEdit: (_, { id }, context) => ({
      delete: () => deleteRetentionRule(context, context.user, id),
      fieldPatch: ({ input }) => retentionRuleEditField(context, context.user, id, input),
    }),
  },
};

export default retentionResolvers;
