import { setRuleActivation } from '../manager/ruleManager';
import { getRule, getRules } from '../domain/rule';
import { internalLoadById } from '../database/middleware';

const ruleResolvers = {
  Query: {
    rule: (_, { id }) => getRule(id),
    rules: () => getRules(),
  },
  Inference: {
    rule: (inf) => getRule(inf.rule),
    explanation: (inf, _, { user }) => inf.explanation.map((e) => internalLoadById(user, e)),
  },
  Mutation: {
    ruleSetActivation: (_, { id, enable }, { user }) => setRuleActivation(user, id, enable),
  },
};

export default ruleResolvers;
