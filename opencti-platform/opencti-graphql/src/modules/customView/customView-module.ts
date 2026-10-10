import type { ModuleDescriptor } from '../module-descriptor';
import { CUSTOM_VIEW_DEFINITION } from './customView';
import customViewTypeDefs from './customView.graphql';
import customViewResolvers from './customView-resolver';

const customViewModule: ModuleDescriptor = {
  id: 'customView',
  dataModel: [CUSTOM_VIEW_DEFINITION],
  graphqlSchemas: [{ schema: customViewTypeDefs, resolver: customViewResolvers }],
};

export default customViewModule;
