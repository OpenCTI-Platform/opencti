import { v4 as uuidv4 } from 'uuid';
import { normalizeName } from '../../schema/identifier';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ENTITY_TYPE_INGESTION_TAXII_COLLECTION, type StixIngestionTaxiiCollection, type StoreEntityIngestionTaxiiCollection } from './ingestion-types';
import { convertIngestionTaxiiCollectionToStix } from './ingestion-converter';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { authorizedMembers } from '../../schema/attribute-definition';

const INGESTION_DEFINITION: ModuleDefinition<StoreEntityIngestionTaxiiCollection, StixIngestionTaxiiCollection> = {
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
    { name: 'confidence_to_score', label: 'Copy confidence level to OpenCTI scores for indicators', type: 'boolean', mandatoryType: 'no', editDefault: true, multiple: false, upsert: false, isFilterable: false },
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
    authorizedMembers
  ],
  relations: [],
  representative: (stix: StixIngestionTaxiiCollection) => {
    return stix.name;
  },
  converter_2_1: convertIngestionTaxiiCollectionToStix
};

registerDefinition(INGESTION_DEFINITION);
