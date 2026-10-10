import type { ModuleDescriptor } from '../module-descriptor';
import { DECAY_RULE_DEFINITION } from './decayRule';
import decayRuleTypeDefs from './decayRule.graphql';
import decayRuleResolvers from './decayRule-resolver';

const decayRuleModule: ModuleDescriptor = {
  id: 'decayRule',
  dataModel: [DECAY_RULE_DEFINITION],
  graphqlSchemas: [{ schema: decayRuleTypeDefs, resolver: decayRuleResolvers }],
};

export default decayRuleModule;
