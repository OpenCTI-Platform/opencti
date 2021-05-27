import { declaredRules } from '../manager/ruleManager';

const ruleResolvers = {
  Query: {
    rule: (_, { id }, { user }) => "",
    rules: () => declaredRules,
  },
  Mutation: {
    changeActivation: (_, { id }, { user }) => console.log(id, user),
  },
  Rule: {
    activated: (rule, _, { user }) => console.log(rule, user),
  },
};

export default ruleResolvers;
