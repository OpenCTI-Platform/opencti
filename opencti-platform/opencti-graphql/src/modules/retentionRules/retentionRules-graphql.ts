import { registerGraphqlSchema } from '../../graphql/schema';
import retentionRulesTypeDefs from './retentionRules.graphql';
import retentionRulesResolver from './retentionRules-resolver';

registerGraphqlSchema({
  schema: retentionRulesTypeDefs,
  resolver: retentionRulesResolver,
});
