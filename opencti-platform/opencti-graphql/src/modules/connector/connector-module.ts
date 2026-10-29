import type { ModuleDescriptor } from '../module-descriptor';
import { CONNECTOR_DEFINITION, CONNECTOR_MANAGER_DEFINITION } from './connector';
import connectorTypeDefs from './connector.graphql';
import connectorResolvers from './connector-resolver';
// Not the ConnectorManager entity type of the data model: the manager that closes old works and deletes completed ones
import { CONNECTOR_MANAGER_DEFINITION as CONNECTOR_WORKS_MANAGER_DEFINITION } from '../../manager/connectorManager';

const connectorModule: ModuleDescriptor = {
  id: 'connector',
  dataModel: [CONNECTOR_DEFINITION, CONNECTOR_MANAGER_DEFINITION],
  graphqlSchemas: [{ schema: connectorTypeDefs, resolver: connectorResolvers }],
  managers: [CONNECTOR_WORKS_MANAGER_DEFINITION],
};

export default connectorModule;
