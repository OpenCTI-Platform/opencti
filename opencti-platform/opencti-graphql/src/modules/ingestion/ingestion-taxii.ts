import { v4 as uuidv4 } from 'uuid';
import { normalizeName } from '../../schema/identifier';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ENTITY_TYPE_INGESTION_TAXII, type StixIngestionTaxii, type StoreEntityIngestionTaxii } from './ingestion-types';
import { convertIngestionTaxiiToStix } from './ingestion-converter';
import ingestionTypeDefs from './ingestion-taxii.graphql';
import ingestionTaxiiResolvers from './ingestion-taxii-resolver';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';

const INGESTION_DEFINITION: ModuleDefinition<StoreEntityIngestionTaxii, StixIngestionTaxii> = {
  type: {
    id: 'ingestion-taxii',
    name: ENTITY_TYPE_INGESTION_TAXII,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  graphql: {
    schema: ingestionTypeDefs,
    resolver: ingestionTaxiiResolvers,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_INGESTION_TAXII]: () => uuidv4(),
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'uri', label: 'URI', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'version', label: 'Version', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'collection', label: 'Collection', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'authentication_type', label: 'Authentication type', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'authentication_value', label: 'Authentication value', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    {
      name: 'user_id',
      label: 'User ID',
      type: 'string',
      format: 'id',
      entityTypes: [ENTITY_TYPE_USER],
      mandatoryType: 'no',
      editDefault: false,
      multiple: false,
      upsert: true,
      isFilterable: true
    },
    { name: 'report_types', label: 'Report types', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: true, upsert: true, isFilterable: true },
    { name: 'created_by_ref', label: 'Created by', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: false },
    { name: 'object_marking_refs', label: 'Marking', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: false },
    { name: 'added_after_start', label: 'Added after', type: 'date', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'current_state_cursor', label: 'Current state cursor', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'ingestion_running', label: 'Running', type: 'boolean', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
  ],
  relations: [],
  representative: (stix: StixIngestionTaxii) => {
    return stix.name;
  },
  converter: convertIngestionTaxiiToStix
};

registerDefinition(INGESTION_DEFINITION);
