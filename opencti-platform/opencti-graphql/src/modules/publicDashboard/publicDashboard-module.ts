import type { ModuleDescriptor } from '../module-descriptor';
import { PUBLIC_DASHBOARD_DEFINITION } from './publicDashboard';
import publicDashboardResolvers from './publicDashboard-resolvers';
import publicDashboardTypeDefs from './publicDashboard.graphql';

const publicDashboardModule: ModuleDescriptor = {
  id: 'publicDashboard',
  dataModel: [PUBLIC_DASHBOARD_DEFINITION],
  graphqlSchemas: [{ schema: publicDashboardTypeDefs, resolver: publicDashboardResolvers }],
};

export default publicDashboardModule;
