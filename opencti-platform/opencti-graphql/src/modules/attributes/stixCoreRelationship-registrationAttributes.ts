import { ABSTRACT_STIX_CORE_RELATIONSHIP } from '../../schema/general';
import { type AttributeDefinition, coverageInformation, customFieldValues, entityType, hasCoveredCoverageInformation, opinionsMetrics } from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { RELATION_HAS_COVERED, STIX_CORE_RELATIONSHIPS } from '../../schema/stixCoreRelationship';
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
  customFieldValues,
];
// coverage_information is filterable on has-covered only
const hasCoveredAttributes: Array<AttributeDefinition> = stixCoreRelationshipsAttributes
  .map((attribute) => (attribute === coverageInformation ? hasCoveredCoverageInformation : attribute));
schemaAttributesDefinition.registerAttributes(ABSTRACT_STIX_CORE_RELATIONSHIP, stixCoreRelationshipsAttributes);
STIX_CORE_RELATIONSHIPS.forEach((type) => {
  schemaAttributesDefinition.registerAttributes(type, type === RELATION_HAS_COVERED ? hasCoveredAttributes : stixCoreRelationshipsAttributes);
});
