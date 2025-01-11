import { registerGraphqlSchema } from '../../../graphql/schema';
import xtmTypeDefs from './xtm.graphql';
import xtm_deprecated from './xtm-resolver';

registerGraphqlSchema({
  schema: xtmTypeDefs,
  resolver: xtm_deprecated,
});
