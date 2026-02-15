import { registerGraphqlSchema } from '../../graphql/schema';
import authenticationProviderTypeDefs from './authenticationProvider.graphql';
import authenticationProviderResolver from './authenticationProvider-resolver';

registerGraphqlSchema({
  schema: authenticationProviderTypeDefs,
  resolver: authenticationProviderResolver,
});
