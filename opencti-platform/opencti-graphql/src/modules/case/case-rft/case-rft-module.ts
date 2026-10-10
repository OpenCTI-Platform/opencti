import type { ModuleDescriptor } from '../../module-descriptor';
import { CASE_RFT_DEFINITION } from './case-rft';
import caseRftTypeDefs from './case-rft.graphql';
import caseRftResolvers from './case-rft-resolvers';

const caseRftModule: ModuleDescriptor = {
  id: 'caseRft',
  dataModel: [CASE_RFT_DEFINITION],
  graphqlSchemas: [{ schema: caseRftTypeDefs, resolver: caseRftResolvers }],
};

export default caseRftModule;
