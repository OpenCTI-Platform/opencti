import type { ModuleDescriptor } from '../../module-descriptor';
import { CASE_RFI_DEFINITION } from './case-rfi';
import caseRfiTypeDefs from './case-rfi.graphql';
import caseRfiResolvers from './case-rfi-resolvers';

const caseRfiModule: ModuleDescriptor = {
  id: 'caseRfi',
  dataModel: [CASE_RFI_DEFINITION],
  graphqlSchemas: [{ schema: caseRfiTypeDefs, resolver: caseRfiResolvers }],
};

export default caseRfiModule;
