import type { Resolvers } from '../../../generated/graphql';
import { addDecayExclusionRule, deleteDecayExclusionRule, fieldPatchDecayExclusionRule, findDecayExclusionRulePaginated, findById } from './decayExclusionRule-domain';

const decayExclusionRuleResolver: Resolvers = {
  Query: {
    decayExclusionRule: (_, { id }, context) => findById(context, context.user, id),
    decayExclusionRules: (_, args, context) => findDecayExclusionRulePaginated(context, context.user, args),
  },
  Mutation: {
    decayExclusionRuleAdd: (_, { input }, context) => {
      return addDecayExclusionRule(context, context.user, input);
    },
    decayExclusionRuleFieldPatch: (_, { id, input }, context) => {
      return fieldPatchDecayExclusionRule(context, context.user, id, input);
    },
    decayExclusionRuleDelete: (_, { id }, context) => {
      return deleteDecayExclusionRule(context, context.user, id);
    },
  },
};

export default decayExclusionRuleResolver;
