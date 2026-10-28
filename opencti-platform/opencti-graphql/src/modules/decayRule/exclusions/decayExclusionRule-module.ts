import type { ModuleDescriptor } from '../../module-descriptor';
import { DECAY_EXCLUSION_RULE_DEFINITION } from './decayExclusionRule';
import decayExclusionRuleTypeDefs from './decayExclusionRule.graphql';
import decayExclusionRuleResolvers from './decayExclusionRule-resolver';

const decayExclusionRuleModule: ModuleDescriptor = {
  id: 'decayExclusionRule',
  dataModel: [DECAY_EXCLUSION_RULE_DEFINITION],
  graphqlSchemas: [{ schema: decayExclusionRuleTypeDefs, resolver: decayExclusionRuleResolvers }],
};

export default decayExclusionRuleModule;
