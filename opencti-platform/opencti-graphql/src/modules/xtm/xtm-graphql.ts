import { registerGraphqlSchema } from '../../graphql/schema';
import xtmTypeDefs from './xtm.graphql';
import xtmResolvers from './xtm-resolver';

registerGraphqlSchema({
  schema: xtmTypeDefs,
  resolver: xtmResolvers,
});
