import { registerGraphqlSchema } from '../../graphql/schema';
import xtmTypeDefs from './xtm.graphql';
import xtmResolvers from './xtm-resolver';
import './deprecated/xtm-deprecated';

registerGraphqlSchema({
  schema: xtmTypeDefs,
  resolver: xtmResolvers,
});
