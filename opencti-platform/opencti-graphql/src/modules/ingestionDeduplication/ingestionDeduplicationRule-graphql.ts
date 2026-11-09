import { registerGraphqlSchema } from '../../graphql/schema';
import ingestionDeduplicationRuleTypeDefs from './ingestionDeduplicationRule.graphql';
import ingestionDeduplicationRuleResolvers from './ingestionDeduplicationRule-resolver';

registerGraphqlSchema({
  schema: ingestionDeduplicationRuleTypeDefs,
  resolver: ingestionDeduplicationRuleResolvers,
});
