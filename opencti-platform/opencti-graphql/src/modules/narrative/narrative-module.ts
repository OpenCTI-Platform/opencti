import type { ModuleDescriptor } from '../module-descriptor';
import { NARRATIVE_DEFINITION } from './narrative';
import narrativeTypeDefs from './narrative.graphql';
import narrativeResolvers from './narrative-resolver';

const narrativeModule: ModuleDescriptor = {
  id: 'narrative',
  dataModel: [NARRATIVE_DEFINITION],
  graphqlSchemas: [{ schema: narrativeTypeDefs, resolver: narrativeResolvers }],
};

export default narrativeModule;
