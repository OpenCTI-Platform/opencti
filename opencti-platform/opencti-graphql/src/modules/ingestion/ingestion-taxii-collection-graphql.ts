import { registerGraphqlSchema } from '../../graphql/schema';
import ingestionTypeDefs from './ingestion-taxii-collection.graphql';
import ingestionTaxiiCollectionResolvers from './ingestion-taxii-collection-resolver';

registerGraphqlSchema({
  schema: ingestionTypeDefs,
  resolver: ingestionTaxiiCollectionResolvers,
});
