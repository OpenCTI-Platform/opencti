import type { Resolvers } from '../../generated/graphql';
import { addDecayRule, countAppliedIndicators, deleteDecayRule, fieldPatchDecayRule, findAll, findById, getDecaySettingsChartData } from './decayRule-domain';

const decayRuleResolvers: Resolvers = {
  Query: {
    decayRule: (_, { id }, context) => findById(context, context.user, id),
    decayRules: (_, args, context) => findAll(context, context.user, args),
  },
  DecayRule: {
    appliedIndicatorsCount: (decayRule, _, context) => countAppliedIndicators(context, context.user, decayRule),
    decaySettingsChartData: (decayRule, _, context) => getDecaySettingsChartData(context, context.user, decayRule),
  },
  Mutation: {
    decayRuleAdd: (_, { input }, context) => {
      return addDecayRule(context, context.user, input);
    },
    decayRuleDelete: (_, { id }, context) => {
      return deleteDecayRule(context, context.user, id);
    },
    decayRuleFieldPatch: (_, { id, input }, context) => {
      return fieldPatchDecayRule(context, context.user, id, input);
    },
  }
};

export default decayRuleResolvers;
