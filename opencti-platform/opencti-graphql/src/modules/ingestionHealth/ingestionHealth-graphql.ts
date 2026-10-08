import { registerGraphqlSchema } from '../../graphql/schema';
import ingestionHealthTypeDefs from './ingestionHealth.graphql';
import ingestionHealthResolvers from './ingestionHealth-resolver';

registerGraphqlSchema({
  schema: ingestionHealthTypeDefs,
  resolver: ingestionHealthResolvers,
});
