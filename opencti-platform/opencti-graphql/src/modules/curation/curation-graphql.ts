import { registerGraphqlSchema } from '../../graphql/schema';
import curationTypeDefs from './curation.graphql';
import curationResolvers from './curation-resolvers';

registerGraphqlSchema({
  schema: curationTypeDefs,
  resolver: curationResolvers,
});
