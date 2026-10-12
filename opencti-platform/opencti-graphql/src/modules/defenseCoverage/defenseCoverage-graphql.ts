import { registerGraphqlSchema } from '../../graphql/schema';
import defenseCoverageTypeDefs from './defenseCoverage.graphql';
import defenseCoverageResolvers from './defenseCoverage-resolvers';

registerGraphqlSchema({
  schema: defenseCoverageTypeDefs,
  resolver: defenseCoverageResolvers,
});
