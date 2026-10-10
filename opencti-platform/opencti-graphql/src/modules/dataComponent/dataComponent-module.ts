import type { ModuleDescriptor } from '../module-descriptor';
import { DATA_COMPONENT_DEFINITION } from './dataComponent';
import dataComponentTypeDefs from './dataComponent.graphql';
import dataComponentResolvers from './dataComponent-resolver';

const dataComponentModule: ModuleDescriptor = {
  id: 'dataComponent',
  dataModel: [DATA_COMPONENT_DEFINITION],
  graphqlSchemas: [{ schema: dataComponentTypeDefs, resolver: dataComponentResolvers }],
};

export default dataComponentModule;
