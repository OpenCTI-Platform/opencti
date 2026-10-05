import { registerGraphqlSchema } from '../../graphql/schema';
import sourceIntelligenceTypeDefs from './sourceIntelligence.graphql';
import sourceIntelligenceResolvers from './sourceIntelligence-resolvers';

registerGraphqlSchema({
  schema: sourceIntelligenceTypeDefs,
  resolver: sourceIntelligenceResolvers,
});
