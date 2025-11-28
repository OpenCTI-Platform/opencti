import { registerGraphqlSchema } from '../../../graphql/schema';
import decayExclusionRuleTypeDefs from './decayExclusionRule.graphql';
import decayExclusionRuleResolvers from './decayExclusionRule-resolver';

registerGraphqlSchema({
  schema: decayExclusionRuleTypeDefs,
  resolver: decayExclusionRuleResolvers,
});
