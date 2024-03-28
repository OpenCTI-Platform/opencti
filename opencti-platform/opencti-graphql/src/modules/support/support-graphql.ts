import { registerGraphqlSchema } from '../../graphql/schema';
import supportTypeDefs from './support.graphql';
import supportResolver from './support-resolver';

registerGraphqlSchema({
  schema: supportTypeDefs,
  resolver: supportResolver,
});
