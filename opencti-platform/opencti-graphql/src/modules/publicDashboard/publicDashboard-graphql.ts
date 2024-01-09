import { registerGraphqlSchema } from '../../graphql/schema';
import publicDashboardResolvers from './publicDashboard-resolvers';
import publicDashboardTypeDefs from './publicDashboard.graphql';

registerGraphqlSchema({
  schema: publicDashboardTypeDefs,
  resolver: publicDashboardResolvers,
});
