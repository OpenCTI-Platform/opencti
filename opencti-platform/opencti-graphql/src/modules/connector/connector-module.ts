import type { ModuleDescriptor } from '../module-descriptor';
import { CONNECTOR_DEFINITION, CONNECTOR_MANAGER_DEFINITION } from './connector';
import connectorTypeDefs from './connector.graphql';
import connectorResolvers from './connector-resolver';

const connectorModule: ModuleDescriptor = {
  id: 'connector',
  dataModel: [CONNECTOR_DEFINITION, CONNECTOR_MANAGER_DEFINITION],
  graphqlSchemas: [{ schema: connectorTypeDefs, resolver: connectorResolvers }],
};

export default connectorModule;
