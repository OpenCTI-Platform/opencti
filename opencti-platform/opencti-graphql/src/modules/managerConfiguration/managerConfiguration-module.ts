import type { ModuleDescriptor } from '../module-descriptor';
import { MANAGER_CONFIGURATION_DEFINITION } from './managerConfiguration';
import managerConfigurationTypeDefs from './managerConfiguration.graphql';
import managerConfigurationResolvers from './managerConfiguration-resolvers';

const managerConfigurationModule: ModuleDescriptor = {
  id: 'managerConfiguration',
  dataModel: [MANAGER_CONFIGURATION_DEFINITION],
  graphqlSchemas: [{ schema: managerConfigurationTypeDefs, resolver: managerConfigurationResolvers }],
};

export default managerConfigurationModule;
