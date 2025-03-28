import { v4 as uuidv4 } from 'uuid';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ENTITY_TYPE_INGESTION_JSON, type StixIngestionJson, type StoreEntityIngestionJson } from './ingestion-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { normalizeName } from '../../schema/identifier';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { convertIngestionJsonToStix } from './ingestion-converter';
import { ENTITY_TYPE_JSON_MAPPER } from '../internal/jsonMapper/jsonMapper-types';

const INGESTION_JSON_DEFINITION: ModuleDefinition<StoreEntityIngestionJson, StixIngestionJson> = {
  type: {
    id: 'ingestion-json',
    name: ENTITY_TYPE_INGESTION_JSON,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_INGESTION_JSON]: () => uuidv4(),
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
    { name: 'uri', label: 'Uri', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'user_id', label: 'User_id', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_USER], mandatoryType: 'external', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'json_mapper_id', label: 'Json_mapper_id', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_JSON_MAPPER], mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'ingestion_running', label: 'Ingestion_running', type: 'boolean', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'added_after_start', label: 'Added_after_start', type: 'date', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'current_state_hash', label: 'Current_state_hash', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'markings', label: 'Markings', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: true, upsert: true, isFilterable: false },
    { name: 'authentication_type', label: 'Authentication type', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'last_execution_date', label: 'Last execution date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'authentication_value', label: 'Authentication value', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
  ],
  relations: [],
  representative: (stix: StixIngestionJson) => {
    return stix.name;
  },
  converter: convertIngestionJsonToStix
};

registerDefinition(INGESTION_JSON_DEFINITION);
