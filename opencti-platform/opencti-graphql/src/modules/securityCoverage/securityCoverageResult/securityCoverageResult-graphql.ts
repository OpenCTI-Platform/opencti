import { registerGraphqlSchema } from '../../../graphql/schema';
import securityCoverageResultResolvers from './securityCoverageResult-resolver';
import securityCoverageResultTypeDefs from './securityCoverageResult.graphql';

registerGraphqlSchema({
  schema: securityCoverageResultTypeDefs,
  resolver: securityCoverageResultResolvers,
});
