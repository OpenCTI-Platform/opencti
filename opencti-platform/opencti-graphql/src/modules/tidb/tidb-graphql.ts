import { registerGraphqlSchema } from '../../graphql/schema';
import tidbResolver from './tidb-resolver';
import tidbTypeDefs from './tidb.graphql';

registerGraphqlSchema({
  schema: tidbTypeDefs,
  resolver: tidbResolver,
});
