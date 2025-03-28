import { registerGraphqlSchema } from '../../graphql/schema';
import ingestionJsonResolvers from './ingestion-json-resolver';
import ingestionTypeDefs from './ingestion-json.graphql';

registerGraphqlSchema({
  schema: ingestionTypeDefs,
  resolver: ingestionJsonResolvers,
});
