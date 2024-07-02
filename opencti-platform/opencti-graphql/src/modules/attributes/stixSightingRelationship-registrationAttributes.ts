import type { AttributeDefinition, IdAttribute, NestedObjectAttribute } from '../../schema/attribute-definition';
import { entityType, internalId } from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { connections } from './basicRelationship-registrationAttributes';
import { ABSTRACT_STIX_CORE_OBJECT } from '../../schema/general';
import {
  INSTANCE_RELATION_FILTER,
  INSTANCE_RELATION_TYPES_FILTER,
  RELATION_FROM_FILTER,
  RELATION_FROM_TYPES_FILTER,
  RELATION_TO_FILTER,
  RELATION_TO_TYPES_FILTER
} from '../../utils/filtering/filtering-constants';

export const stixSightingRelationshipsAttributes: Array<AttributeDefinition> = [
  { ...entityType, isFilterable: false },
  { name: 'attribute_count', label: 'Count', type: 'numeric', precision: 'integer', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
  { name: 'first_seen', label: 'First seen', type: 'date', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
  { name: 'last_seen', label: 'Last seen', type: 'date', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
  { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
  { name: 'x_opencti_negative', label: 'False positive', type: 'boolean', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: false, isFilterable: true },
  { name: 'x_opencti_workflow_id', label: 'Workflow status', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
  { ...connections as NestedObjectAttribute,
    isFilterable: true,
    mappings: [
      { ...internalId as IdAttribute,
        isFilterable: true,
        entityTypes: [ABSTRACT_STIX_CORE_OBJECT],
        associatedFilterKeys: [
          { key: RELATION_FROM_FILTER, label: 'Source entity' },
          { key: RELATION_TO_FILTER, label: 'Target entity' },
          { key: INSTANCE_RELATION_FILTER, label: 'Related entity' }
        ]
      },
      { name: 'name', label: 'Name', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: false },
      { name: 'role', label: 'Role', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: false },
      { name: 'types', label: 'Types', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: true, associatedFilterKeys: [{ key: RELATION_FROM_TYPES_FILTER, label: 'Source type' }, { key: RELATION_TO_TYPES_FILTER, label: 'Target type' }, { key: INSTANCE_RELATION_TYPES_FILTER, label: 'Related type' }] },
    ],
  },
];

schemaAttributesDefinition.registerAttributes(STIX_SIGHTING_RELATIONSHIP, stixSightingRelationshipsAttributes);
