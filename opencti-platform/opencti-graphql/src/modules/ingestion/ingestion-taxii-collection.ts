import { v4 as uuidv4 } from 'uuid';
import { normalizeName } from '../../schema/identifier';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ENTITY_TYPE_INGESTION_TAXII_COLLECTION, type StixIngestionTaxii, type StoreEntityIngestionTaxii } from './ingestion-types';
import { convertIngestionTaxiiToStix } from './ingestion-converter';

const INGESTION_DEFINITION: ModuleDefinition<StoreEntityIngestionTaxii, StixIngestionTaxii> = {
  type: {
    id: 'ingestion-taxii-collection',
    name: ENTITY_TYPE_INGESTION_TAXII_COLLECTION,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_INGESTION_TAXII_COLLECTION]: () => uuidv4(),
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
    { name: 'ingestion_running', label: 'Ingestion running', type: 'boolean', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
  ],
  relations: [],
  representative: (stix: StixIngestionTaxii) => {
    return stix.name;
  },
  converter: convertIngestionTaxiiToStix
};

registerDefinition(INGESTION_DEFINITION);
