import type { ModuleDescriptor } from '../module-descriptor';
import { DATA_SOURCE_DEFINITION } from './dataSource';
import dataSourceTypeDefs from './dataSource.graphql';
import dataSourceResolvers from './dataSource-resolvers';

const dataSourceModule: ModuleDescriptor = {
  id: 'dataSource',
  dataModel: [DATA_SOURCE_DEFINITION],
  graphqlSchemas: [{ schema: dataSourceTypeDefs, resolver: dataSourceResolvers }],
};

export default dataSourceModule;
