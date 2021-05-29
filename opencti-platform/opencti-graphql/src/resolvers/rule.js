import { declaredRules, getRule } from '../manager/ruleManager';

const ruleResolvers = {
  Query: {
    rule: (_, { id }) => getRule(id),
    rules: () => declaredRules,
  },
  Mutation: {
    changeActivation: () => ({}),
  },
  Rule: {
    activated: () => ({}),
  },
};

export default ruleResolvers;
