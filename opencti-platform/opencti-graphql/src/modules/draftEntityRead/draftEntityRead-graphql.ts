import { registerGraphqlSchema } from '../../graphql/schema';
import draftEntityReadTypeDefs from './draftEntityRead.graphql';
import draftEntityReadResolver from './draftEntityRead-resolver';

registerGraphqlSchema({
  schema: draftEntityReadTypeDefs,
  resolver: draftEntityReadResolver,
});
