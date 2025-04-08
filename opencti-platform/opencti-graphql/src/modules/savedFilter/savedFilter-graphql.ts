import { registerGraphqlSchema } from '../../graphql/schema';
import savedFilterTypeDefs from './savedFilter.graphql';
import savedFilterResolver from './savedFilter-resolver';

registerGraphqlSchema({
  schema: savedFilterTypeDefs,
  resolver: savedFilterResolver
});
