import { cleanRuleManager, getManagerInfo, ruleApply, ruleClear, rulesRescan } from '../manager/ruleManager';
import { getRules, setRuleActivation, getRule } from '../domain/rules';
import { internalLoadById } from '../database/middleware-loader';

const ruleResolvers = {
  Query: {
    rule: (_, { id }, context) => getRule(context, context.user, id),
    rules: (_, __, context) => getRules(context, context.user),
    ruleManagerInfo: (_, __, context) => getManagerInfo(context, context.user),
  },
  Inference: {
    rule: (inf, _, context) => getRule(context, context.user, inf.rule),
    explanation: (inf, _, context) => inf.explanation.map((e) => internalLoadById(context, context.user, e)),
  },
  Mutation: {
    ruleSetActivation: (_, { id, enable }, context) => setRuleActivation(context, context.user, id, enable),
    ruleManagerClean: (_, { eventId }, context) => cleanRuleManager(context, context.user, eventId),
    ruleApply: (_, { elementId, ruleId }, context) => ruleApply(context, context.user, elementId, ruleId),
    ruleClear: (_, { elementId, ruleId }, context) => ruleClear(context, context.user, elementId, ruleId),
    rulesRescan: (_, { elementId }, context) => rulesRescan(context, context.user, elementId),
  },
};

export default ruleResolvers;
