import type { ModuleDescriptor } from '../../module-descriptor';
import { SECURITY_COVERAGE_RESULT_DEFINITION } from './securityCoverageResult';
import securityCoverageResultResolvers from './securityCoverageResult-resolver';
import securityCoverageResultTypeDefs from './securityCoverageResult.graphql';

const securityCoverageResultModule: ModuleDescriptor = {
  id: 'securityCoverageResult',
  dataModel: [SECURITY_COVERAGE_RESULT_DEFINITION],
  graphqlSchemas: [{ schema: securityCoverageResultTypeDefs, resolver: securityCoverageResultResolvers }],
};

export default securityCoverageResultModule;
