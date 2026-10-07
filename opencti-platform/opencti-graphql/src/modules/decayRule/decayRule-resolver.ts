import type { DecayRuleTargetScope, KnowledgeFreshnessPolicy, Resolvers } from '../../generated/graphql';
import {
  addDecayRule,
  countAppliedIndicators,
  createKnowledgeDecayRule,
  deleteDecayRule,
  fieldPatchDecayRule,
  findDecayRulePaginated,
  findById,
  getDecaySettingsChartData,
} from './decayRule-domain';
import { countKnowledgeDecayRulesInvolved, getDecayRuleScope } from './decayRule-knowledge';

const decayRuleResolvers: Resolvers = {
  Query: {
    decayRule: (_, { id }, context) => findById(context, context.user, id),
    decayRules: (_, args, context) => findDecayRulePaginated(context, context.user, args),
    knowledgeDecayRulesInvolvedCount: (_, __, context) => countKnowledgeDecayRulesInvolved(context, context.user),
  },
  DecayRule: {
    appliedIndicatorsCount: (decayRule, _, context) => countAppliedIndicators(context, context.user, decayRule),
    decaySettingsChartData: (decayRule, _, context) => getDecaySettingsChartData(context, context.user, decayRule),
    // Knowledge decay rules have no indicator score curve
    decay_lifetime: (decayRule) => decayRule.decay_lifetime ?? 0,
    decay_pound: (decayRule) => decayRule.decay_pound ?? 0,
    decay_revoke_score: (decayRule) => decayRule.decay_revoke_score ?? 0,
    target_scope: (decayRule) => getDecayRuleScope(decayRule) as DecayRuleTargetScope,
    freshness_policy: (decayRule) => (decayRule.freshness_policy ?? null) as KnowledgeFreshnessPolicy | null,
    staleElementsCount: (decayRule, _, context) => context.batch.staleElementsCountBatchLoader.load(decayRule),
  },
  Mutation: {
    decayRuleAdd: (_, { input }, context) => {
      return addDecayRule(context, context.user, input);
    },
    knowledgeDecayRuleAdd: (_, { input }, context) => {
      return createKnowledgeDecayRule(context, context.user, input);
    },
    decayRuleDelete: (_, { id }, context) => {
      return deleteDecayRule(context, context.user, id);
    },
    decayRuleFieldPatch: (_, { id, input }, context) => {
      return fieldPatchDecayRule(context, context.user, id, input);
    },
  },
};

export default decayRuleResolvers;
