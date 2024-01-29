import { v4 as uuidv4 } from 'uuid';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ENTITY_TYPE_INGESTION_CSV, type StixIngestionCsv, type StoreEntityIngestionCsv } from './ingestion-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { normalizeName } from '../../schema/identifier';
import ingestionTypeDefs from './ingestion-csv.graphql';
import { convertIngestionCsvToStix } from './ingestion-converter';
import ingestionCsvResolvers from './ingestion-csv-resolver';

const INGESTION_CSV_DEFINITION: ModuleDefinition<StoreEntityIngestionCsv, StixIngestionCsv> = {
  type: {
    id: 'ingestion-csv',
    name: ENTITY_TYPE_INGESTION_CSV,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  graphql: {
    schema: ingestionTypeDefs,
    resolver: ingestionCsvResolvers,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_INGESTION_CSV]: () => uuidv4(),
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [
    { name: 'name', type: 'string', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true },
    { name: 'description', type: 'string', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true },
    { name: 'uri', type: 'string', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true },
    { name: 'user_id', type: 'string', mandatoryType: 'external', editDefault: false, multiple: false, upsert: true },
    { name: 'csvMapper_id', type: 'string', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true },
    { name: 'ingestion_running', type: 'boolean', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true },
  ],
  relations: [],
  representative: (stix: StixIngestionCsv) => {
    return stix.name;
  },
  converter: convertIngestionCsvToStix
};

registerDefinition(INGESTION_CSV_DEFINITION);
