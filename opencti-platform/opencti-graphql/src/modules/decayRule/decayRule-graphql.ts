import { registerGraphqlSchema } from '../../graphql/schema';
import decayRuleTypeDefs from './decayRule.graphql';
import decayRuleResolvers from './decayRule-resolver';

registerGraphqlSchema({
  schema: decayRuleTypeDefs,
  resolver: decayRuleResolvers,
});
