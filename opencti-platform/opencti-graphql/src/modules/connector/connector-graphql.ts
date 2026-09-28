import { registerGraphqlSchema } from '../../graphql/schema';
import connectorTypeDefs from './connector.graphql';
import connectorResolvers from './connector-resolver';

registerGraphqlSchema({
  schema: connectorTypeDefs,
  resolver: connectorResolvers,
});
