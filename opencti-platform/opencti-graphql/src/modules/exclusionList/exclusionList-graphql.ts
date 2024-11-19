import { registerGraphqlSchema } from '../../graphql/schema';
import exclusionListTypeDefs from './exclusionList.graphql';
import exclusionListResolver from './exclusionList-resolver';

registerGraphqlSchema({
  schema: exclusionListTypeDefs,
  resolver: exclusionListResolver
});
