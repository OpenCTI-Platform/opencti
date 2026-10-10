import type { ModuleDescriptor } from '../module-descriptor';
import { SECURITY_COVERAGE_DEFINITION } from './securityCoverage';
import securityCoverageResolvers from './securityCoverage-resolver';
import securityCoverageTypeDefs from './securityCoverage.graphql';

const securityCoverageModule: ModuleDescriptor = {
  id: 'securityCoverage',
  dataModel: [SECURITY_COVERAGE_DEFINITION],
  graphqlSchemas: [{ schema: securityCoverageTypeDefs, resolver: securityCoverageResolvers }],
};

export default securityCoverageModule;
