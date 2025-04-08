import { registerGraphqlSchema } from '../../graphql/schema';
import requestAccessResolvers from './requestAccess-resolver';
import requestAccessTypeDefs from './requestAccess.graphql';

registerGraphqlSchema({
  schema: requestAccessTypeDefs,
  resolver: requestAccessResolvers,
});
