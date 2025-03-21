import { registerGraphqlSchema } from '../../graphql/schema';
import authTypeDefs from './auth.graphql';
import authResolvers from './auth-resolver';

registerGraphqlSchema({
  schema: authTypeDefs,
  resolver: authResolvers,
});
