import {
  createRetentionRule,
  deleteRetentionRule,
  findAll,
  findById,
  retentionRuleEditField,
} from '../domain/retentionRule';

const retentionResolvers = {
  Query: {
    retentionRule: (_, { id }, { user }) => findById(user, id),
    retentionRules: (_, args, { user }) => findAll(user, args),
  },
  Mutation: {
    retentionRuleAdd: (_, { input }, { user }) => createRetentionRule(user, input),
    retentionRuleEdit: (_, { id }, { user }) => ({
      delete: () => deleteRetentionRule(user, id),
      fieldPatch: ({ input }) => retentionRuleEditField(user, id, input),
    }),
  },
};

export default retentionResolvers;
