import type { ModuleDescriptor } from '../module-descriptor';
import { GROUPING_DEFINITION } from './grouping';
import groupingTypeDefs from './grouping.graphql';
import groupingResolvers from './grouping-resolver';

const groupingModule: ModuleDescriptor = {
  id: 'grouping',
  dataModel: [GROUPING_DEFINITION],
  graphqlSchemas: [{ schema: groupingTypeDefs, resolver: groupingResolvers }],
};

export default groupingModule;
