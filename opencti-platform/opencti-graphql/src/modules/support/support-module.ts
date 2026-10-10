import type { ModuleDescriptor } from '../module-descriptor';
import { SUPPORT_PACKAGE_DEFINITION } from './support';
import supportTypeDefs from './support.graphql';
import supportResolver from './support-resolver';

const supportModule: ModuleDescriptor = {
  id: 'support',
  dataModel: [SUPPORT_PACKAGE_DEFINITION],
  graphqlSchemas: [{ schema: supportTypeDefs, resolver: supportResolver }],
};

export default supportModule;
