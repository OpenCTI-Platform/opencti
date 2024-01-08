import { registerGraphqlSchema } from '../../graphql/schema';
import caseTypeDefs from './case.graphql';
import caseResolvers from './case-resolvers';

registerGraphqlSchema({
  schema: caseTypeDefs,
  resolver: caseResolvers,
});
