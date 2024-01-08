import { registerGraphqlSchema } from '../../../graphql/schema';
import caseRfiTypeDefs from './case-rfi.graphql';
import caseRfiResolvers from './case-rfi-resolvers';

registerGraphqlSchema({
  schema: caseRfiTypeDefs,
  resolver: caseRfiResolvers,
});
