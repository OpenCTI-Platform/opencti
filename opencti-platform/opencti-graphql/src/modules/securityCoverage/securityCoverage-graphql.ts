import { registerGraphqlSchema } from '../../graphql/schema';
import securityCoverageResolvers from './securityCoverage-resolver';
import securityCoverageTypeDefs from './securityCoverage.graphql';

registerGraphqlSchema({
  schema: securityCoverageTypeDefs,
  resolver: securityCoverageResolvers,
});
