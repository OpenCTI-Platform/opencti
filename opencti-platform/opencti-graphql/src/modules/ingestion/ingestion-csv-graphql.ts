import { registerGraphqlSchema } from '../../graphql/schema';
import ingestionCsvResolvers from './ingestion-csv-resolver';
import ingestionTypeDefs from './ingestion-csv.graphql';

registerGraphqlSchema({
  schema: ingestionTypeDefs,
  resolver: ingestionCsvResolvers,
});
