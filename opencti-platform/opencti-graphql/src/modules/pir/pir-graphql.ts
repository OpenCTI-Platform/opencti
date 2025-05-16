import { registerGraphqlSchema } from '../../graphql/schema';
import pirTypeDefs from './pir.graphql';
import pirResolvers from './pir-resolvers';

registerGraphqlSchema({
  schema: pirTypeDefs,
  resolver: pirResolvers,
});
