import { getRules, getRule, setRuleActivation } from '../manager/ruleManager';

const ruleResolvers = {
  Query: {
    rule: (_, { id }) => getRule(id),
    rules: () => getRules(),
  },
  Mutation: {
    ruleSetActivation: (_, { id, enable }, { user }) => setRuleActivation(user, id, enable),
  },
};

export default ruleResolvers;
