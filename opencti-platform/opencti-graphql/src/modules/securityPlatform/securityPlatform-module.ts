import type { ModuleDescriptor } from '../module-descriptor';
import { SECURITY_PLATFORM_DEFINITION } from './securityPlatform';
import securityPlatformResolvers from './securityPlatform-resolver';
import securityPlatformTypeDefs from './securityPlatform.graphql';

const securityPlatformModule: ModuleDescriptor = {
  id: 'securityPlatform',
  dataModel: [SECURITY_PLATFORM_DEFINITION],
  graphqlSchemas: [{ schema: securityPlatformTypeDefs, resolver: securityPlatformResolvers }],
};

export default securityPlatformModule;
