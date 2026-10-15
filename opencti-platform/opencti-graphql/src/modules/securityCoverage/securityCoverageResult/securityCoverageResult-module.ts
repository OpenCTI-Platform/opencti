import type { ModuleDescriptor } from '../../module-descriptor';
import { SECURITY_COVERAGE_RESULT_DEFINITION } from './securityCoverageResult';
import securityCoverageResultResolvers from './securityCoverageResult-resolver';
import securityCoverageResultTypeDefs from './securityCoverageResult.graphql';
import { coverageInformation } from '../../../schema/attribute-definition';
import { RELATION_HAS_COVERED } from '../../../schema/stixCoreRelationship';

const securityCoverageResultModule: ModuleDescriptor = {
  id: 'securityCoverageResult',
  dataModel: [SECURITY_COVERAGE_RESULT_DEFINITION],
  // The coverage information of a tested entity is carried by its has-covered relationship only
  attributes: [{ entityType: RELATION_HAS_COVERED, attributes: [coverageInformation] }],
  graphqlSchemas: [{ schema: securityCoverageResultTypeDefs, resolver: securityCoverageResultResolvers }],
};

export default securityCoverageResultModule;
