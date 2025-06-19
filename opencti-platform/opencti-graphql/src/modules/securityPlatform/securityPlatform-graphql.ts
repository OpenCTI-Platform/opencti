import { registerGraphqlSchema } from '../../graphql/schema';
import securityPlatformResolvers from './securityPlatform-resolver';
import securityPlatformTypeDefs from './securityPlatform.graphql';

registerGraphqlSchema({
  schema: securityPlatformTypeDefs,
  resolver: securityPlatformResolvers,
});
