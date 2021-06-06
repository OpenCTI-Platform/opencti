import { getRules, getRule, setRuleActivation } from '../manager/ruleManager';

const ruleResolvers = {
  Query: {
    rule: (_, { id }) => getRule(id),
    rules: () => getRules(),
  },
  Mutation: {
    ruleSetActivation: (_, { id, enable }) => setRuleActivation(id, enable),
  },
};

export default ruleResolvers;
