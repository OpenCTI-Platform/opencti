import { registerGraphqlSchema } from '../../graphql/schema';
import narrativeTypeDefs from './narrative.graphql';
import narrativeResolvers from './narrative-resolver';

registerGraphqlSchema({
  schema: narrativeTypeDefs,
  resolver: narrativeResolvers,
});
