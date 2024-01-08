import { registerGraphqlSchema } from '../../../graphql/schema';
import caseRftTypeDefs from './case-rft.graphql';
import caseRftResolvers from './case-rft-resolvers';

registerGraphqlSchema({
  schema: caseRftTypeDefs,
  resolver: caseRftResolvers,
});
