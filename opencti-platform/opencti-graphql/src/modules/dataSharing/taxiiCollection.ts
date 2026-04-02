import { v4 as uuidv4 } from 'uuid';
import convertTaxiiCollectionToStix from './taxiiCollection-converter';
import { ENTITY_TYPE_TAXII_COLLECTION, type StoreEntityTaxiiCollection, type StixTaxiiCollection } from './taxiiCollection-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { authorizedMembers } from '../../schema/attribute-definition';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';

const TAXII_COLLECTION_DEFINITION: ModuleDefinition<StoreEntityTaxiiCollection, StixTaxiiCollection> = {
  type: {
    id: 'taxii-collection',
    name: ENTITY_TYPE_TAXII_COLLECTION,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_TAXII_COLLECTION]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'filters', label: 'Filters', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'taxii_public', label: 'Public taxii', type: 'boolean', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    { name: 'taxii_public_user_id', label: 'Public taxii user id', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_USER], mandatoryType: 'no', editDefault: true, multiple: false, upsert: false, isFilterable: false },
    { name: 'include_inferences', label: 'Include inferences', type: 'boolean', mandatoryType: 'no', editDefault: true, multiple: false, upsert: false, isFilterable: false },
    { name: 'score_to_confidence', label: 'Copy OpenCTI scores to confidence level for indicators', type: 'boolean', mandatoryType: 'no', editDefault: true, multiple: false, upsert: false, isFilterable: false },
    authorizedMembers,
  ],
  relations: [],
  representative: (instance: StixTaxiiCollection) => {
    return instance.name;
  },
  converter_2_1: convertTaxiiCollectionToStix,
};

registerDefinition(TAXII_COLLECTION_DEFINITION);
