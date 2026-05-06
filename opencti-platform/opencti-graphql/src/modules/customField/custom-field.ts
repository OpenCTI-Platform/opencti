import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import type { StixCustomField, StoreEntityCustomField } from './custom-field-types';
import { ENTITY_TYPE_CUSTOM_FIELD } from './custom-field-types';
import convertCustomFieldToStix from './custom-field-converter';

const CUSTOM_FIELD_DEFINITION: ModuleDefinition<StoreEntityCustomField, StixCustomField> = {
  type: {
    id: 'custom-field',
    name: ENTITY_TYPE_CUSTOM_FIELD,
    category: ABSTRACT_INTERNAL_OBJECT,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_CUSTOM_FIELD]: [{ src: 'name' }, { src: 'entity_types' }],
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'label', label: 'Label', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'field_type', label: 'Field type', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'entity_types', label: 'Entity types', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: true, isFilterable: true },
    { name: 'mandatory', label: 'Mandatory', type: 'boolean', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    // Integer-specific
    { name: 'default_value', label: 'Default value', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'min_value', label: 'Min value', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'max_value', label: 'Max value', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
  ],
  relations: [],
  relationsRefs: [],
  representative: (stix: StixCustomField) => {
    return stix.label ?? stix.name;
  },
  converter_2_1: convertCustomFieldToStix,
};

registerDefinition(CUSTOM_FIELD_DEFINITION);

