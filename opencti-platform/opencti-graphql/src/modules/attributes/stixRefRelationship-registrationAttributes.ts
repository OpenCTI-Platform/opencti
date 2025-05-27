import type { AttributeDefinition } from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { ABSTRACT_STIX_REF_RELATIONSHIP } from '../../schema/general';

// -- ATTRIBUTES -

const stixRefRelationshipsAttributes: AttributeDefinition[] = [
  { name: 'start_time', label: 'Start date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
  { name: 'stop_time', label: 'End date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
  {
    name: 'pir_score',
    label: 'PIR Score',
    type: 'numeric',
    precision: 'integer',
    mandatoryType: 'no',
    editDefault: false,
    multiple: false,
    upsert: true,
    isFilterable: true,
    featureFlag: 'Pir',
  },
  {
    name: 'pir_explanations',
    label: 'PIR Explanations',
    type: 'object',
    format: 'flat',
    mandatoryType: 'no',
    editDefault: false,
    multiple: true,
    upsert: true,
    isFilterable: true,
    featureFlag: 'Pir',
  },
];

schemaAttributesDefinition.registerAttributes(ABSTRACT_STIX_REF_RELATIONSHIP, stixRefRelationshipsAttributes);
