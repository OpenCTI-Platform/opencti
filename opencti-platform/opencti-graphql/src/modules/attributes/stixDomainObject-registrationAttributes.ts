import * as R from 'ramda';
import { CUSTOM_FIELDS_FEATURE_FLAG } from '../../config/conf';
import {
  aliases,
  type AttributeDefinition,
  authorizedMembers,
  authorizedMembersActivationDate,
  confidence,
  created,
  entityLocationType,
  files,
  iAliasedIds,
  type IdAttribute,
  identityClass,
  lang,
  modified,
  revoked,
  xOpenctiAliases,
  xOpenctiModifiedAt,
  xOpenctiReliability,
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
} from '../../schema/stixDomainObject';
import { ENTITY_TYPE_PIR } from '../pir/pir-types';
import { ENTITY_TYPE_STATUS } from '../../schema/internalObject';
import { X_WORKFLOW_ID } from '../../schema/identifier';
import { DefaultFormating } from '../../utils/humanize';
import type { BasicWorkflowStatus } from '../../types/store';

export const workflowId: IdAttribute = {
  name: X_WORKFLOW_ID,
  label: 'Workflow status',
  type: 'string',
  format: 'id',
  entityTypes: [ENTITY_TYPE_STATUS],
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: true,
  isFilterable: false,
  attrRawIds: async (item, getEntitiesMapFromCache) => {
    const platformStatuses = await getEntitiesMapFromCache<BasicWorkflowStatus>(ENTITY_TYPE_STATUS);
    const templateId = platformStatuses.get(item)?.template_id;
    return templateId ? [{ id: templateId, source: item }] : [];
  },
  representative: (item, translate, _ = DefaultFormating): string => {
    return translate[item];
  },
};

const stixDomainObjectAttributes: Array<AttributeDefinition<any>> = [
  created,
  modified,
  xOpenctiModifiedAt,
  lang,
  confidence,
  revoked,
  files,
  { name: 'x_opencti_graph_data', label: 'Graph data', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  workflowId,
  {
    name: 'pir_information',
    label: 'PIR information',
    type: 'object',
    format: 'nested',
    editDefault: false,
    mandatoryType: 'internal',
    multiple: true,
    upsert: false,
    isFilterable: false,
    mappings: [
      { name: 'pir_id', label: 'PIR ID', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_PIR], editDefault: false, mandatoryType: 'no', multiple: false, upsert: true, isFilterable: true },
      { name: 'pir_score', label: 'PIR Score', type: 'numeric', precision: 'integer', editDefault: false, mandatoryType: 'no', multiple: false, upsert: true, isFilterable: true },
      { name: 'last_pir_score_date', label: 'Last score evolution', type: 'date', editDefault: false, mandatoryType: 'no', multiple: false, upsert: true, isFilterable: true },
    ],
  },
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

const stixDomainObjectsAttributes: { [k: string]: Array<AttributeDefinition<any>> } = {
  [ENTITY_TYPE_ATTACK_PATTERN]: [
    aliases,
    iAliasedIds,
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_mitre_platforms', label: 'Platforms', type: 'string', format: 'vocabulary', vocabularyCategory: 'platforms_ov', mandatoryType: 'no', editDefault: false, multiple: true, upsert: true, isFilterable: true },
    { name: 'x_mitre_permissions_required', label: 'Permissions required', type: 'string', format: 'vocabulary', vocabularyCategory: 'permissions_ov', mandatoryType: 'no', editDefault: false, multiple: true, upsert: true, isFilterable: true },
    { name: 'x_mitre_detection', label: 'Detection', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_mitre_id', label: 'External ID', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: false },
    { ...revoked, isFilterable: true },
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
    { name: 'content', label: 'Content', type: 'string', format: 'short', mandatoryType: 'no', editDefault: true, multiple: false, upsert: true, isFilterable: true },
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
    { ...authorizedMembers, editDefault: true },
    { ...authorizedMembersActivationDate },
  ],
  [ENTITY_TYPE_COURSE_OF_ACTION]: [
    xOpenctiAliases,
    iAliasedIds,
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_mitre_id', label: 'External ID', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_opencti_threat_hunting', label: 'Threat hunting', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_opencti_log_sources', label: 'Log sources', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: true, isFilterable: true },
    { ...revoked, isFilterable: true },
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
    { name: 'x_opencti_score', label: 'Score', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
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
    { name: 'street_address', label: 'Street address', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: false, isFilterable: true },
  ],
  [ENTITY_TYPE_MALWARE]: [
    aliases,
    iAliasedIds,
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'malware_types', label: 'Malware types', type: 'string', format: 'vocabulary', vocabularyCategory: 'malware_type_ov', mandatoryType: 'customizable', editDefault: true, multiple: true, upsert: true, isFilterable: true },
    { name: 'x_opencti_score', label: 'Score', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
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
    { name: 'x_opencti_score', label: 'Score', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
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
  [ENTITY_TYPE_INCIDENT]: [
    // Check Name, type, mandatory, multiple, upsert
    iAliasedIds,
    aliases,
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'incident_type', label: 'Incident type', type: 'string', format: 'vocabulary', vocabularyCategory: 'incident_type_ov', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'severity', label: 'Severity', type: 'string', format: 'vocabulary', vocabularyCategory: 'incident_severity_ov', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'source', label: 'Source', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_opencti_score', label: 'Score', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'first_seen', label: 'First seen', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'last_seen', label: 'Last seen', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'objective', label: 'Objective', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
  ],
};
R.forEachObjIndexed((value, key) => schemaAttributesDefinition.registerAttributes(key as string, value), stixDomainObjectsAttributes);

// Custom field values — registered once at boot, content is dynamic (no restart needed)
schemaAttributesDefinition.registerAttributes(ABSTRACT_STIX_DOMAIN_OBJECT, [
  {
    name: 'custom_field_values',
    label: 'Custom field values',
    type: 'object',
    format: 'nested',
    mandatoryType: 'no',
    editDefault: false,
    multiple: true,
    upsert: true,
    isFilterable: false,
    featureFlag: CUSTOM_FIELDS_FEATURE_FLAG,
    mappings: [
      { name: 'field_id', label: 'Field ID', type: 'string', format: 'short', mandatoryType: 'internal', upsert: false, editDefault: false, multiple: false, isFilterable: false },
      { name: 'field_name', label: 'Field name', type: 'string', format: 'short', mandatoryType: 'internal', upsert: false, editDefault: false, multiple: false, isFilterable: false },
      { name: 'int_value', label: 'Integer value', type: 'numeric', precision: 'integer', mandatoryType: 'no', upsert: false, editDefault: false, multiple: false, isFilterable: false },
      { name: 'string_value', label: 'String value', type: 'string', format: 'short', mandatoryType: 'no', upsert: false, editDefault: false, multiple: false, isFilterable: false },
      { name: 'boolean_value', label: 'Boolean value', type: 'boolean', mandatoryType: 'no', upsert: false, editDefault: false, multiple: false, isFilterable: false },
      { name: 'date_value', label: 'Date value', type: 'date', mandatoryType: 'no', upsert: false, editDefault: false, multiple: false, isFilterable: false },
      { name: 'select_value', label: 'Select value', type: 'string', format: 'short', mandatoryType: 'no', upsert: false, editDefault: false, multiple: false, isFilterable: false },
      { name: 'select_values', label: 'Select values', type: 'string', format: 'short', mandatoryType: 'no', upsert: false, editDefault: false, multiple: true, isFilterable: false },
    ],
  },
]);
