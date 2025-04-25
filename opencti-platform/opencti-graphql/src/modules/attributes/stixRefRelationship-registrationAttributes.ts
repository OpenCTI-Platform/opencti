import type { AttributeDefinition } from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, ABSTRACT_STIX_REF_RELATIONSHIP } from '../../schema/general';

// -- ATTRIBUTES -

const stixRefRelationshipsAttributes: AttributeDefinition[] = [
  { name: 'start_time', label: 'Start date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
  { name: 'stop_time', label: 'End date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
  {
    name: 'pir_explanations',
    label: 'PIR explanations',
    type: 'object',
    format: 'nested',
    mandatoryType: 'no',
    editDefault: false,
    multiple: true,
    upsert: true,
    isFilterable: true,
    mappings: [
      {
        name: 'relationship_id',
        label: 'Matching relationship ID',
        type: 'string',
        format: 'id',
        entityTypes: [ABSTRACT_STIX_CORE_RELATIONSHIP],
        editDefault: false,
        mandatoryType: 'no',
        multiple: false,
        upsert: true,
        isFilterable: true
      },
      {
        name: 'criterion_id',
        label: 'Matching PIR criterion ID',
        type: 'string',
        format: 'short',
        editDefault: false,
        mandatoryType: 'no',
        multiple: false,
        upsert: true,
        isFilterable: false
      },
    ]
  },
];

schemaAttributesDefinition.registerAttributes(ABSTRACT_STIX_REF_RELATIONSHIP, stixRefRelationshipsAttributes);
