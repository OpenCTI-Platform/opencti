import * as R from 'ramda';
import {
  aliases,
  type AttributeDefinition,
  confidence,
  created,
  entityLocationType,
  files,
  iAliasedIds,
  identityClass,
  lang,
  modified,
  revoked,
  xOpenctiAliases,
  xOpenctiReliability
} from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { ABSTRACT_STIX_DOMAIN_OBJECT, ENTITY_TYPE_CONTAINER, ENTITY_TYPE_IDENTITY, ENTITY_TYPE_LOCATION, ENTITY_TYPE_THREAT_ACTOR } from '../../schema/general';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_COURSE_OF_ACTION,
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_IDENTITY_SYSTEM,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_POSITION,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR_GROUP,
  ENTITY_TYPE_TOOL,
  ENTITY_TYPE_VULNERABILITY
} from '../../schema/stixDomainObject';

const stixDomainObjectAttributes: Array<AttributeDefinition> = [
  created,
  modified,
  lang,
  confidence,
  revoked,
  files,
  { name: 'x_opencti_graph_data', label: 'Graph data', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: 'x_opencti_workflow_id', label: 'Workflow status', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false }
];
schemaAttributesDefinition.registerAttributes(ABSTRACT_STIX_DOMAIN_OBJECT, stixDomainObjectAttributes);

const stixDomainObjectIdentityAttributes: Array<AttributeDefinition> = [
  { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
  { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
  { name: 'contact_information', label: 'Contact information', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
  { name: 'roles', label: 'Roles', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
  identityClass,
];
schemaAttributesDefinition.registerAttributes(ENTITY_TYPE_IDENTITY, stixDomainObjectIdentityAttributes);

const stixDomainObjectLocationAttributes: Array<AttributeDefinition> = [
  { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
  { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
  { name: 'latitude', label: 'Latitude', type: 'numeric', precision: 'float', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
  { name: 'longitude', label: 'Longitude', type: 'numeric', precision: 'float', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
  { name: 'precision', label: 'Precision', type: 'numeric', precision: 'float', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  entityLocationType,
];
schemaAttributesDefinition.registerAttributes(ENTITY_TYPE_LOCATION, stixDomainObjectLocationAttributes);

const stixDomainObjectContainerAttributes: Array<AttributeDefinition> = [];
schemaAttributesDefinition.registerAttributes(ENTITY_TYPE_CONTAINER, stixDomainObjectContainerAttributes);

const stixDomainObjectsAttributes: { [k: string]: Array<AttributeDefinition> } = {
  [ENTITY_TYPE_ATTACK_PATTERN]: [
    aliases,
    iAliasedIds,
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_mitre_platforms', label: 'Platforms', type: 'string', format: 'vocabulary', vocabularyCategory: 'platforms_ov', mandatoryType: 'no', editDefault: false, multiple: true, upsert: true, isFilterable: true },
    { name: 'x_mitre_permissions_required', label: 'Permissions required', type: 'string', format: 'vocabulary', vocabularyCategory: 'permissions_ov', mandatoryType: 'no', editDefault: false, multiple: true, upsert: true, isFilterable: true },
    { name: 'x_mitre_detection', label: 'Detection', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_mitre_id', label: 'External ID', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: false },
  ],
  [ENTITY_TYPE_CAMPAIGN]: [
    aliases,
    iAliasedIds,
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'first_seen', label: 'First seen', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'last_seen', label: 'Last seen', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'objective', label: 'Objective', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  ],
  [ENTITY_TYPE_CONTAINER_NOTE]: [
    { ...created, mandatoryType: 'external', editDefault: true },
    { name: 'attribute_abstract', label: 'Abstract', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'content', label: 'Content', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'authors', label: 'Authors', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'note_types', label: 'Note types', type: 'string', format: 'vocabulary', vocabularyCategory: 'note_types_ov', mandatoryType: 'customizable', editDefault: true, multiple: true, upsert: true, isFilterable: true },
    { name: 'likelihood', label: 'Likelihood', type: 'numeric', precision: 'integer', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'content_mapping', label: 'Content mapping', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
  ],
  [ENTITY_TYPE_CONTAINER_OBSERVED_DATA]: [
    { name: 'first_observed', label: 'First observed', type: 'date', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'last_observed', label: 'Last observed', type: 'date', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'number_observed', label: 'Number observed', type: 'numeric', precision: 'integer', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'content', label: 'Content', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'content_mapping', label: 'Content mapping', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
  ],
  [ENTITY_TYPE_CONTAINER_OPINION]: [
    { name: 'explanation', label: 'Explanation', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'authors', label: 'Authors', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'opinion', label: 'Opinion', type: 'string', format: 'vocabulary', vocabularyCategory: 'opinion_ov', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'content', label: 'Content', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'content_mapping', label: 'Content mapping', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
  ],
  [ENTITY_TYPE_CONTAINER_REPORT]: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'report_types', label: 'Report types', type: 'string', format: 'vocabulary', vocabularyCategory: 'report_types_ov', mandatoryType: 'customizable', editDefault: true, multiple: true, upsert: true, isFilterable: true },
    xOpenctiReliability,
    { name: 'published', label: 'Report publication date', type: 'date', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    { name: 'content', label: 'Content', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'content_mapping', label: 'Content mapping', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
  ],
  [ENTITY_TYPE_COURSE_OF_ACTION]: [
    xOpenctiAliases,
    iAliasedIds,
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_mitre_id', label: 'External ID', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_opencti_threat_hunting', label: 'Threat hunting', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_opencti_log_sources', label: 'Log sources', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: true, isFilterable: true },
  ],
  [ENTITY_TYPE_IDENTITY_INDIVIDUAL]: [
    xOpenctiAliases,
    iAliasedIds,
    xOpenctiReliability,
    { name: 'x_opencti_firstname', label: 'Firstname', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'x_opencti_lastname', label: 'Lastname', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  ],
  [ENTITY_TYPE_IDENTITY_SECTOR]: [
    xOpenctiAliases,
    iAliasedIds,
  ],
  [ENTITY_TYPE_IDENTITY_SYSTEM]: [
    xOpenctiAliases,
    iAliasedIds,
    xOpenctiReliability,
  ],
  [ENTITY_TYPE_INFRASTRUCTURE]: [
    aliases,
    iAliasedIds,
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'infrastructure_types', label: 'Infrastructure types', type: 'string', format: 'vocabulary', vocabularyCategory: 'infrastructure_type_ov', mandatoryType: 'customizable', editDefault: true, multiple: true, upsert: false, isFilterable: true },
    { name: 'first_seen', label: 'First seen', type: 'date', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    { name: 'last_seen', label: 'Last seen', type: 'date', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: false, isFilterable: true },
  ],
  [ENTITY_TYPE_INTRUSION_SET]: [
    aliases,
    iAliasedIds,
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'first_seen', label: 'First seen', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'last_seen', label: 'Last seen', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'goals', label: 'Goals', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: true, isFilterable: true },
    { name: 'resource_level', label: 'Resource level', type: 'string', format: 'vocabulary', vocabularyCategory: 'attack_resource_level_ov', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'primary_motivation', label: 'Primary motivation', type: 'string', format: 'vocabulary', vocabularyCategory: 'attack_motivation_ov', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'secondary_motivations', label: 'Secondary motivation', type: 'string', format: 'vocabulary', vocabularyCategory: 'attack_motivation_ov', mandatoryType: 'no', editDefault: false, multiple: true, upsert: true, isFilterable: true },
  ],
  [ENTITY_TYPE_LOCATION_CITY]: [
    xOpenctiAliases,
    iAliasedIds,
  ],
  [ENTITY_TYPE_LOCATION_COUNTRY]: [
    xOpenctiAliases,
    iAliasedIds,
  ],
  [ENTITY_TYPE_LOCATION_REGION]: [
    xOpenctiAliases,
    iAliasedIds,
  ],
  [ENTITY_TYPE_LOCATION_POSITION]: [
    xOpenctiAliases,
    iAliasedIds,
    { name: 'postal_code', label: 'Postal code', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    { name: 'street_address', label: 'Street address', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: false, isFilterable: true }
  ],
  [ENTITY_TYPE_MALWARE]: [
    aliases,
    iAliasedIds,
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'malware_types', label: 'Malware types', type: 'string', format: 'vocabulary', vocabularyCategory: 'malware_type_ov', mandatoryType: 'customizable', editDefault: true, multiple: true, upsert: true, isFilterable: true },
    { name: 'is_family', label: 'Is family', type: 'boolean', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'first_seen', label: 'First seen', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'last_seen', label: 'Last seen', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'architecture_execution_envs', label: 'Architecture execution env.', type: 'string', format: 'vocabulary', vocabularyCategory: 'processor_architecture_ov', mandatoryType: 'customizable', editDefault: true, multiple: true, upsert: true, isFilterable: true },
    { name: 'implementation_languages', label: 'Implementation languages', type: 'string', format: 'vocabulary', vocabularyCategory: 'implementation_language_ov', mandatoryType: 'customizable', editDefault: true, multiple: true, upsert: true, isFilterable: true },
    { name: 'capabilities', label: 'Capabilities', type: 'string', format: 'vocabulary', vocabularyCategory: 'malware_capabilities_ov', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: true },
  ],
  [ENTITY_TYPE_THREAT_ACTOR_GROUP]: [
    iAliasedIds,
    aliases,
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'threat_actor_types', label: 'Threat actor types', format: 'vocabulary', type: 'string', vocabularyCategory: 'threat_actor_group_type_ov', mandatoryType: 'customizable', editDefault: true, multiple: true, upsert: false, isFilterable: true },
    { name: 'first_seen', label: 'First seen', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'last_seen', label: 'Last seen', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'goals', label: 'Goals', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: true, isFilterable: true },
    { name: 'roles', label: 'Roles', type: 'string', format: 'vocabulary', vocabularyCategory: 'threat_actor_group_role_ov', mandatoryType: 'no', editDefault: false, multiple: true, upsert: true, isFilterable: true },
    { name: 'sophistication', label: 'Sophistication', format: 'vocabulary', type: 'string', vocabularyCategory: 'threat_actor_group_sophistication_ov', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'resource_level', label: 'Resource level', type: 'string', format: 'vocabulary', vocabularyCategory: 'attack_resource_level_ov', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'primary_motivation', label: 'Primary motivation', type: 'string', format: 'vocabulary', vocabularyCategory: 'attack_motivation_ov', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'secondary_motivations', label: 'Secondary motivation', type: 'string', format: 'vocabulary', vocabularyCategory: 'attack_motivation_ov', mandatoryType: 'no', editDefault: false, multiple: true, upsert: true, isFilterable: true },
    { name: 'personal_motivations', label: 'Personal motivation', type: 'string', format: 'vocabulary', vocabularyCategory: 'attack_motivation_ov', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
  ],
  [ENTITY_TYPE_THREAT_ACTOR]: [],
  [ENTITY_TYPE_TOOL]: [
    iAliasedIds,
    aliases,
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'tool_types', label: 'Tool types', type: 'string', format: 'vocabulary', vocabularyCategory: 'tool_types_ov', mandatoryType: 'customizable', editDefault: true, multiple: true, upsert: false, isFilterable: true },
    { name: 'tool_version', label: 'Tool version', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  ],
  [ENTITY_TYPE_VULNERABILITY]: [
    iAliasedIds,
    xOpenctiAliases,
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_opencti_cvss_base_score', label: 'CVSS3 Score', type: 'numeric', precision: 'float', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_opencti_cvss_base_severity', label: 'CVSS3 Severity', type: 'string', format: 'enum', values: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'Unknown'], mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_opencti_cvss_attack_vector', label: 'CVSS3 Attack vector', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_opencti_cvss_integrity_impact', label: 'CVSS3 Integrity impact', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_opencti_cvss_availability_impact', label: 'CVSS3 Availability impact', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_opencti_cvss_confidentiality_impact', label: 'CVSS3 Confidentiality impact', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
  ],
  [ENTITY_TYPE_INCIDENT]: [
    // Check Name, type, mandatory, multiple, upsert
    iAliasedIds,
    aliases,
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'incident_type', label: 'Incident type', type: 'string', format: 'vocabulary', vocabularyCategory: 'incident_type_ov', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'severity', label: 'Severity', type: 'string', format: 'vocabulary', vocabularyCategory: 'incident_severity_ov', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'source', label: 'Source', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'first_seen', label: 'First seen', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'last_seen', label: 'Last seen', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'objective', label: 'Objective', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
  ],
};
R.forEachObjIndexed((value, key) => schemaAttributesDefinition.registerAttributes(key as string, value), stixDomainObjectsAttributes);
