import { registerGraphqlSchema } from '../../graphql/schema';
import ingestionHealthResolver from './ingestionHealth-resolver';
import ingestionHealthTypeDefs from './ingestionHealth.graphql';

registerGraphqlSchema({
  schema: ingestionHealthTypeDefs,
  resolver: ingestionHealthResolver,
});
