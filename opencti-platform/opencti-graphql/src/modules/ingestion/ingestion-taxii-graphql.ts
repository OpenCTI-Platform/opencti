import { registerGraphqlSchema } from '../../graphql/schema';
import ingestionTypeDefs from './ingestion-taxii.graphql';
import ingestionTaxiiResolvers from './ingestion-taxii-resolver';

registerGraphqlSchema({
  schema: ingestionTypeDefs,
  resolver: ingestionTaxiiResolvers,
});
