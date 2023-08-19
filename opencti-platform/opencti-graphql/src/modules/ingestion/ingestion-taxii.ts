import { v4 as uuidv4 } from 'uuid';
import { normalizeName } from '../../schema/identifier';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { ModuleDefinition, registerDefinition } from '../../schema/module';
import {
  ENTITY_TYPE_INGESTION_TAXII,
  StixIngestionTaxii,
  StoreEntityIngestionTaxii
} from './ingestion-types';
import { convertIngestionTaxiiToStix } from './ingestion-converter';
import ingestionTypeDefs from './ingestion-taxii.graphql';
import ingestionTaxiiResolvers from './ingestion-taxii-resolver';

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
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'description', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
    { name: 'uri', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
    { name: 'version', type: 'string', mandatoryType: 'internal', multiple: false, upsert: true },
    { name: 'authentication_type', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'authentication_value', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'user_id', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'report_types', type: 'string', mandatoryType: 'external', multiple: true, upsert: true },
    { name: 'created_by_ref', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'object_marking_refs', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'added_after_start', type: 'date', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'current_state_cursor', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'ingestion_running', type: 'boolean', mandatoryType: 'external', multiple: false, upsert: true },
  ],
  relations: [],
  representative: (stix: StixIngestionTaxii) => {
    return stix.name;
  },
  converter: convertIngestionTaxiiToStix
};

registerDefinition(INGESTION_DEFINITION);
