import { v4 as uuidv4 } from 'uuid';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ENTITY_TYPE_INGESTION_CSV, type StixIngestionCsv, type StoreEntityIngestionCsv } from './ingestion-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { normalizeName } from '../../schema/identifier';
import { convertIngestionCsvToStix } from './ingestion-converter';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { ENTITY_TYPE_CSV_MAPPER } from '../internal/csvMapper/csvMapper-types';
import { INGESTION_HEALTH_FEATURE_FLAG } from '../../config/conf';

const INGESTION_CSV_DEFINITION: ModuleDefinition<StoreEntityIngestionCsv, StixIngestionCsv> = {
  type: {
    id: 'ingestion-csv',
    name: ENTITY_TYPE_INGESTION_CSV,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
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
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'scheduling_period', label: 'Scheduling period', type: 'string', format: 'text', mandatoryType: 'no', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'uri', label: 'Uri', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'user_id', label: 'User_id', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_USER], mandatoryType: 'external', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'csv_mapper_type', label: 'Csv_mapper_type', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'csv_mapper', label: 'Csv_mapper', type: 'string', format: 'json', mandatoryType: 'external', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'csv_mapper_id', label: 'Csv_mapper_id', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_CSV_MAPPER], mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'ingestion_running', label: 'Ingestion_running', type: 'boolean', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'added_after_start', label: 'Added_after_start', type: 'date', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'current_state_hash', label: 'Current_state_hash', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'markings', label: 'Markings', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: true, upsert: true, isFilterable: false },
    { name: 'authentication_type', label: 'Authentication type', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'last_execution_date', label: 'Last execution date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    // `ingestionManager` patches this on every run and the GraphQL schema has always
    // exposed it, but it was never registered here — so the write was silently dropped
    // and the field read back null. Registering it makes the existing patch effective.
    { name: 'last_execution_status', label: 'Last execution status', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'authentication_value', label: 'Authentication value', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'ssl_verify', label: 'Verify SSL certificate', type: 'boolean', mandatoryType: 'no', editDefault: true, multiple: false, upsert: true, isFilterable: false },
    // Cached ingestion health, written by the health manager on change only.
    // The resolver stays the source of truth — these exist so the fleet can be
    // filtered and sorted server-side, which a value computed on read cannot do.
    // Registered behind the feature flag, so with it off they are absent from
    // the mapping entirely rather than present and always empty.
    { name: 'ingestion_health_status', label: 'Health status', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true, featureFlag: INGESTION_HEALTH_FEATURE_FLAG },
    { name: 'ingestion_health_since', label: 'Health since', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true, featureFlag: INGESTION_HEALTH_FEATURE_FLAG },
    { name: 'ingestion_last_productive_at', label: 'Last productive run', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true, featureFlag: INGESTION_HEALTH_FEATURE_FLAG },
    { name: 'ingestion_configuration_status', label: 'Configuration status', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true, featureFlag: INGESTION_HEALTH_FEATURE_FLAG },
  ],
  relations: [],
  representative: (stix: StixIngestionCsv) => {
    return stix.name;
  },
  converter_2_1: convertIngestionCsvToStix,
};

registerDefinition(INGESTION_CSV_DEFINITION);
