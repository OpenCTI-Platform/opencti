import { registerGraphqlSchema } from '../../../graphql/schema';
import xtmHubTypeDefs from './xtm-hub.graphql';
import xtmHubResolvers from './xtm-hub-resolver';

registerGraphqlSchema({
  schema: xtmHubTypeDefs,
  resolver: xtmHubResolvers,
});
