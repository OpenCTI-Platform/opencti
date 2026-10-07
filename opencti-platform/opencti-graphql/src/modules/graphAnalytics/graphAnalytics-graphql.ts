import { registerGraphqlSchema } from '../../graphql/schema';
import graphAnalyticsTypeDefs from './graphAnalytics.graphql';
import graphAnalyticsResolvers from './graphAnalytics-resolvers';

registerGraphqlSchema({
  schema: graphAnalyticsTypeDefs,
  resolver: graphAnalyticsResolvers,
});
