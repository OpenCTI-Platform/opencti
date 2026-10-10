import type { ModuleDescriptor } from '../module-descriptor';
import authTypeDefs from './auth.graphql';
import authResolvers from './auth-resolver';

const authModule: ModuleDescriptor = {
  id: 'auth',
  graphqlSchemas: [{ schema: authTypeDefs, resolver: authResolvers }],
};

export default authModule;
