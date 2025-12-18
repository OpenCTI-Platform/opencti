import { ABSTRACT_STIX_CORE_RELATIONSHIP } from '../../schema/general';
import { type AttributeDefinition, coverageInformation, entityType, opinionsMetrics } from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { STIX_CORE_RELATIONSHIPS } from '../../schema/stixCoreRelationship';
import { connections } from './basicRelationship-registrationAttributes';
import { workflowId } from './stixDomainObject-registrationAttributes';

export const stixCoreRelationshipsAttributes: Array<AttributeDefinition> = [
  entityType,
  opinionsMetrics,
  coverageInformation,
  { ...connections, isFilterable: true },
  { name: 'start_time', label: 'Start time', type: 'date', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
  { name: 'stop_time', label: 'Stop time', type: 'date', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
  { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
  workflowId,
];
schemaAttributesDefinition.registerAttributes(ABSTRACT_STIX_CORE_RELATIONSHIP, stixCoreRelationshipsAttributes);
STIX_CORE_RELATIONSHIPS.map((type) => schemaAttributesDefinition.registerAttributes(type, stixCoreRelationshipsAttributes));
