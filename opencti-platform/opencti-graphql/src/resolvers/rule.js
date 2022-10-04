import { cleanRuleManager, getManagerInfo } from '../manager/ruleManager';
import { internalLoadById } from '../database/middleware';
import { getRules, setRuleActivation, getRule } from '../domain/rules';

const ruleResolvers = {
  Query: {
    rule: (_, { id }, context) => getRule(context, id),
    rules: (_, __, context) => getRules(context),
    ruleManagerInfo: (_, __, context) => getManagerInfo(context, context.user),
  },
  Inference: {
    rule: (inf, _, context) => getRule(context, inf.rule),
    explanation: (inf, _, context) => inf.explanation.map((e) => internalLoadById(context, context.user, e)),
  },
  Mutation: {
    ruleSetActivation: (_, { id, enable }, context) => setRuleActivation(context, context.user, id, enable),
    ruleManagerClean: (_, { eventId }, context) => cleanRuleManager(context, context.user, eventId),
  },
};

export default ruleResolvers;
