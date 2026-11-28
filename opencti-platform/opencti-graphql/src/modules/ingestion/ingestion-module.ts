import type { ModuleDescriptor } from '../module-descriptor';
import { INGESTION_RSS_DEFINITION } from './ingestion-rss';
import { INGESTION_TAXII_DEFINITION } from './ingestion-taxii';
import { INGESTION_CSV_DEFINITION } from './ingestion-csv';
import { INGESTION_JSON_DEFINITION } from './ingestion-json';
import { INGESTION_TAXII_COLLECTION_DEFINITION } from './ingestion-taxii-collection';
import ingestionRssTypeDefs from './ingestion-rss.graphql';
import ingestionRssResolvers from './ingestion-rss-resolver';
import ingestionTaxiiTypeDefs from './ingestion-taxii.graphql';
import ingestionTaxiiResolvers from './ingestion-taxii-resolver';
import ingestionTaxiiCollectionTypeDefs from './ingestion-taxii-collection.graphql';
import ingestionTaxiiCollectionResolvers from './ingestion-taxii-collection-resolver';
import ingestionCsvResolvers from './ingestion-csv-resolver';
import ingestionCsvTypeDefs from './ingestion-csv.graphql';
import ingestionJsonResolvers from './ingestion-json-resolver';
import ingestionJsonTypeDefs from './ingestion-json.graphql';

const ingestionModule: ModuleDescriptor = {
  id: 'ingestion',
  dataModel: [INGESTION_RSS_DEFINITION, INGESTION_TAXII_DEFINITION, INGESTION_CSV_DEFINITION, INGESTION_JSON_DEFINITION, INGESTION_TAXII_COLLECTION_DEFINITION],
  graphqlSchemas: [
    { schema: ingestionRssTypeDefs, resolver: ingestionRssResolvers },
    { schema: ingestionTaxiiTypeDefs, resolver: ingestionTaxiiResolvers },
    { schema: ingestionTaxiiCollectionTypeDefs, resolver: ingestionTaxiiCollectionResolvers },
    { schema: ingestionCsvTypeDefs, resolver: ingestionCsvResolvers },
    { schema: ingestionJsonTypeDefs, resolver: ingestionJsonResolvers },
  ],
};

export default ingestionModule;
