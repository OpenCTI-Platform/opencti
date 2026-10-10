import type { ModuleDescriptor } from '../module-descriptor';
import { DISSEMINATION_LIST_DEFINITION } from './disseminationList';
import disseminationListTypeDefs from './disseminationList.graphql';
import disseminationListResolvers from './disseminationList-resolver';

const disseminationListModule: ModuleDescriptor = {
  id: 'disseminationList',
  dataModel: [DISSEMINATION_LIST_DEFINITION],
  graphqlSchemas: [{ schema: disseminationListTypeDefs, resolver: disseminationListResolvers }],
};

export default disseminationListModule;
