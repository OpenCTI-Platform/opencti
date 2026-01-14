import { registerGraphqlSchema } from '../../graphql/schema';
import ingestionTypeDefs from './ingestion.graphql';
import ingestionResolvers from './ingestion-resolver';

registerGraphqlSchema({
  schema: ingestionTypeDefs,
  resolver: ingestionResolvers,
});
