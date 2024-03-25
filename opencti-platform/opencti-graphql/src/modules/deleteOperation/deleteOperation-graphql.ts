import { registerGraphqlSchema } from '../../graphql/schema';
import deleteOperationTypeDefs from './deleteOperation.graphql';
import deleteOperationResolvers from './deleteOperation-resolvers';

registerGraphqlSchema({
  schema: deleteOperationTypeDefs,
  resolver: deleteOperationResolvers,
});
