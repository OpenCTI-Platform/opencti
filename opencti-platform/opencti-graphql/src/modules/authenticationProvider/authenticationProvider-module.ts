import type { ModuleDescriptor } from '../module-descriptor';
import { AUTHENTICATION_PROVIDER_DEFINITION } from './authenticationProvider';
import authenticationProviderTypeDefs from './authenticationProvider.graphql';
import authenticationProviderResolver from './authenticationProvider-resolver';

const authenticationProviderModule: ModuleDescriptor = {
  id: 'authenticationProvider',
  dataModel: [AUTHENTICATION_PROVIDER_DEFINITION],
  graphqlSchemas: [{ schema: authenticationProviderTypeDefs, resolver: authenticationProviderResolver }],
};

export default authenticationProviderModule;
