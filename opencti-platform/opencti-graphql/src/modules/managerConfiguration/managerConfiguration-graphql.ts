import { registerGraphqlSchema } from '../../graphql/schema';
import managerConfigurationTypeDefs from './managerConfiguration.graphql';
import managerConfigurationResolvers from './managerConfiguration-resolvers';

registerGraphqlSchema({
  schema: managerConfigurationTypeDefs,
  resolver: managerConfigurationResolvers,
});
