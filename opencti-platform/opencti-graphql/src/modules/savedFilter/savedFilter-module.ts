import type { ModuleDescriptor } from '../module-descriptor';
import { SAVED_FILTER_DEFINITION } from './savedFilter';
import savedFilterTypeDefs from './savedFilter.graphql';
import savedFilterResolver from './savedFilter-resolver';

const savedFilterModule: ModuleDescriptor = {
  id: 'savedFilter',
  dataModel: [SAVED_FILTER_DEFINITION],
  graphqlSchemas: [{ schema: savedFilterTypeDefs, resolver: savedFilterResolver }],
};

export default savedFilterModule;
