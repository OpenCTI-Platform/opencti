import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP } from '../../schema/general';
import type { AttributeDefinition, IdAttribute, NestedObjectAttribute } from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { STIX_CORE_RELATIONSHIPS } from '../../schema/stixCoreRelationship';
import { connections } from './basicRelationship-registrationAttributes';
import { internalId } from '../../schema/attribute-definition';
import {
  INSTANCE_RELATION_TYPES_FILTER,
  INSTANCE_RELATION_FILTER,
  RELATION_FROM_FILTER,
  RELATION_FROM_TYPES_FILTER,
  RELATION_TO_FILTER,
  RELATION_TO_TYPES_FILTER
} from '../../utils/filtering/filtering-constants';

export const stixCoreRelationshipsAttributes: Array<AttributeDefinition> = [
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
  { name: 'entity_type', label: 'Entity type', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: false },
  { name: 'start_time', label: 'First observation', type: 'date', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
  { name: 'stop_time', label: 'Last observation', type: 'date', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
  { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
  { name: 'x_opencti_workflow_id', label: 'Workflow status', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
];
schemaAttributesDefinition.registerAttributes(ABSTRACT_STIX_CORE_RELATIONSHIP, stixCoreRelationshipsAttributes);
STIX_CORE_RELATIONSHIPS.map((type) => schemaAttributesDefinition.registerAttributes(type, stixCoreRelationshipsAttributes));
