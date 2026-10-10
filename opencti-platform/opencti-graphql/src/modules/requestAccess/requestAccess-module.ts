import type { ModuleDescriptor } from '../module-descriptor';
import requestAccessResolvers from './requestAccess-resolver';
import requestAccessTypeDefs from './requestAccess.graphql';

const requestAccessModule: ModuleDescriptor = {
  id: 'requestAccess',
  graphqlSchemas: [{ schema: requestAccessTypeDefs, resolver: requestAccessResolvers }],
};

export default requestAccessModule;
