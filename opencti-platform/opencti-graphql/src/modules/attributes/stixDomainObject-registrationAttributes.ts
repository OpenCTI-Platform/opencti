import * as R from 'ramda';
import {
  aliases,
  AttributeDefinition,
  confidence,
  created,
  entityLocationType,
  iAliasedIds,
  lang,
  revoked,
  xOpenctiAliases
} from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { ABSTRACT_STIX_DOMAIN_OBJECT, ENTITY_TYPE_IDENTITY, ENTITY_TYPE_LOCATION } from '../../schema/general';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_COURSE_OF_ACTION,
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_IDENTITY_SYSTEM,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INDICATOR,
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
  lang,
  confidence,
  revoked,
  { name: 'x_opencti_graph_data', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
  { name: 'x_opencti_workflow_id', type: 'string', mandatoryType: 'no', multiple: false, upsert: false }
];
schemaAttributesDefinition.registerAttributes(ABSTRACT_STIX_DOMAIN_OBJECT, stixDomainObjectAttributes);

const stixDomainObjectIdentityAttributes: Array<AttributeDefinition> = [
  { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
  { name: 'description', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
  { name: 'contact_information', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
  { name: 'identity_class', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
  { name: 'roles', type: 'string', mandatoryType: 'no', multiple: true, upsert: false },
];
schemaAttributesDefinition.registerAttributes(ENTITY_TYPE_IDENTITY, stixDomainObjectIdentityAttributes);

const stixDomainObjectLocationAttributes: Array<AttributeDefinition> = [
  { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
  { name: 'description', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
  { name: 'latitude', type: 'numeric', mandatoryType: 'no', multiple: false, upsert: true },
  { name: 'longitude', type: 'numeric', mandatoryType: 'no', multiple: false, upsert: true },
  { name: 'precision', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
  entityLocationType,
];
schemaAttributesDefinition.registerAttributes(ENTITY_TYPE_LOCATION, stixDomainObjectLocationAttributes);

const stixDomainObjectsAttributes: { [k: string]: Array<AttributeDefinition> } = {
  [ENTITY_TYPE_ATTACK_PATTERN]: [
    aliases,
    iAliasedIds,
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'description', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
    {
      name: 'x_mitre_platforms',
      type: 'string',
      mandatoryType: 'no',
      multiple: true,
      upsert: true,
      label: 'Platforms'
    },
    { name: 'x_mitre_permissions_required', type: 'string', mandatoryType: 'no', multiple: true, upsert: true },
    { name: 'x_mitre_detection', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    {
      name: 'x_mitre_id',
      type: 'string',
      mandatoryType: 'customizable',
      multiple: false,
      upsert: true,
      label: 'External ID'
    },
  ],
  [ENTITY_TYPE_CAMPAIGN]: [
    aliases,
    iAliasedIds,
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'description', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
    { name: 'first_seen', type: 'date', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'last_seen', type: 'date', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'objective', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
  ],
  [ENTITY_TYPE_CONTAINER_NOTE]: [
    { ...created, mandatoryType: 'external', label: 'Publication date' },
    { name: 'abstract', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    {
      name: 'attribute_abstract',
      type: 'string',
      mandatoryType: 'customizable',
      multiple: false,
      upsert: true,
      label: 'Abstract'
    },
    { name: 'content', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'authors', type: 'string', mandatoryType: 'no', multiple: true, upsert: false },
    {
      name: 'note_types',
      type: 'string',
      mandatoryType: 'customizable',
      multiple: true,
      upsert: true,
      label: 'Note types'
    },
    { name: 'likelihood', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true, label: 'Likelihood' },
    { name: 'content_mapping', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
  ],
  [ENTITY_TYPE_CONTAINER_OBSERVED_DATA]: [
    {
      name: 'first_observed',
      type: 'date',
      mandatoryType: 'external',
      multiple: false,
      upsert: false,
      label: 'First observed'
    },
    {
      name: 'last_observed',
      type: 'date',
      mandatoryType: 'external',
      multiple: false,
      upsert: false,
      label: 'Last observed'
    },
    {
      name: 'number_observed',
      type: 'numeric',
      mandatoryType: 'external',
      multiple: false,
      upsert: false,
      label: 'Number observed'
    },
    { name: 'content', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
    { name: 'content_mapping', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
  ],
  [ENTITY_TYPE_CONTAINER_OPINION]: [
    { name: 'explanation', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
    { name: 'authors', type: 'string', mandatoryType: 'no', multiple: true, upsert: false },
    { name: 'opinion', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'content', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
    { name: 'content_mapping', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
  ],
  [ENTITY_TYPE_CONTAINER_REPORT]: [
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'description', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
    {
      name: 'report_types',
      type: 'string',
      mandatoryType: 'customizable',
      multiple: true,
      upsert: true,
      label: 'Report types'
    },
    { name: 'published', type: 'date', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'content', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
    { name: 'content_mapping', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
  ],
  [ENTITY_TYPE_COURSE_OF_ACTION]: [
    xOpenctiAliases,
    iAliasedIds,
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'description', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
    { name: 'x_mitre_id', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'x_opencti_threat_hunting', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'x_opencti_log_sources', type: 'string', mandatoryType: 'no', multiple: true, upsert: true },
  ],
  [ENTITY_TYPE_IDENTITY_INDIVIDUAL]: [
    xOpenctiAliases,
    iAliasedIds,
    { name: 'x_opencti_firstname', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'x_opencti_lastname', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
  ],
  [ENTITY_TYPE_IDENTITY_ORGANIZATION]: [
    xOpenctiAliases,
    iAliasedIds,
    { name: 'default_dashboard', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    {
      name: 'x_opencti_organization_type',
      type: 'string',
      mandatoryType: 'no',
      multiple: false,
      upsert: false,
      label: 'Organization type'
    },
    {
      name: 'x_opencti_reliability',
      type: 'string',
      mandatoryType: 'no',
      multiple: false,
      upsert: false,
      label: 'Reliability'
    },
  ],
  [ENTITY_TYPE_IDENTITY_SECTOR]: [
    xOpenctiAliases,
    iAliasedIds,
  ],
  [ENTITY_TYPE_IDENTITY_SYSTEM]: [
    xOpenctiAliases,
    iAliasedIds,
  ],
  [ENTITY_TYPE_INDICATOR]: [
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'description', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
    {
      name: 'pattern_type',
      type: 'string',
      mandatoryType: 'external',
      multiple: false,
      upsert: false,
      label: 'Pattern type'
    },
    { name: 'pattern_version', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'pattern', type: 'string', mandatoryType: 'external', multiple: false, upsert: false },
    {
      name: 'indicator_types',
      type: 'string',
      mandatoryType: 'customizable',
      multiple: true,
      upsert: true,
      label: 'Indicator types'
    },
    {
      name: 'valid_from',
      type: 'date',
      mandatoryType: 'customizable',
      multiple: false,
      upsert: true,
      label: 'Valid from'
    },
    {
      name: 'valid_until',
      type: 'date',
      mandatoryType: 'customizable',
      multiple: false,
      upsert: true,
      label: 'Valid until'
    },
    {
      name: 'x_opencti_score',
      type: 'numeric',
      mandatoryType: 'customizable',
      multiple: false,
      upsert: true,
      label: 'Score'
    },
    { name: 'x_opencti_detection', type: 'boolean', mandatoryType: 'no', multiple: false, upsert: true },
    {
      name: 'x_opencti_main_observable_type',
      type: 'string',
      mandatoryType: 'external',
      multiple: false,
      upsert: true,
      label: 'Main observable type'
    },
    {
      name: 'x_mitre_platforms',
      type: 'string',
      mandatoryType: 'customizable',
      multiple: true,
      upsert: true,
      label: 'Platforms'
    },
  ],
  [ENTITY_TYPE_INFRASTRUCTURE]: [
    aliases,
    iAliasedIds,
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'description', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
    {
      name: 'infrastructure_types',
      type: 'string',
      mandatoryType: 'customizable',
      multiple: true,
      upsert: false,
      label: 'Infrastructure types'
    },
    {
      name: 'first_seen',
      type: 'date',
      mandatoryType: 'customizable',
      multiple: false,
      upsert: false,
      label: 'First seen'
    },
    {
      name: 'last_seen',
      type: 'date',
      mandatoryType: 'customizable',
      multiple: false,
      upsert: false,
      label: 'Last seen'
    },
  ],
  [ENTITY_TYPE_INTRUSION_SET]: [
    aliases,
    iAliasedIds,
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'description', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
    { name: 'first_seen', type: 'date', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'last_seen', type: 'date', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'goals', type: 'string', mandatoryType: 'no', multiple: true, upsert: true },
    { name: 'resource_level', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'primary_motivation', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'secondary_motivations', type: 'string', mandatoryType: 'no', multiple: true, upsert: true },
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
    {
      name: 'postal_code',
      type: 'string',
      mandatoryType: 'customizable',
      multiple: false,
      upsert: false,
      label: 'Postal code'
    },
    {
      name: 'street_address',
      type: 'string',
      mandatoryType: 'customizable',
      multiple: false,
      upsert: false,
      label: 'Street address'
    }
  ],
  [ENTITY_TYPE_MALWARE]: [
    aliases,
    iAliasedIds,
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'description', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
    {
      name: 'malware_types',
      type: 'string',
      mandatoryType: 'customizable',
      multiple: true,
      upsert: true,
      label: 'Malware types'
    },
    {
      name: 'is_family',
      type: 'boolean',
      mandatoryType: 'external',
      multiple: false,
      upsert: true,
      label: 'Is family'
    },
    { name: 'first_seen', type: 'date', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'last_seen', type: 'date', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'architecture_execution_envs', type: 'string', mandatoryType: 'customizable', multiple: true, upsert: true, label: 'Architecture execution env.' },
    { name: 'implementation_languages', type: 'string', mandatoryType: 'customizable', multiple: true, upsert: true, label: 'Implementation languages' },
    { name: 'capabilities', type: 'string', mandatoryType: 'no', multiple: true, upsert: false },
  ],
  [ENTITY_TYPE_THREAT_ACTOR_GROUP]: [
    aliases,
    iAliasedIds,
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'description', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
    {
      name: 'threat_actor_types',
      type: 'string',
      mandatoryType: 'customizable',
      multiple: true,
      upsert: false,
      label: 'Threat actor types'
    },
    { name: 'first_seen', type: 'date', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'last_seen', type: 'date', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'goals', type: 'string', mandatoryType: 'no', multiple: true, upsert: true },
    { name: 'roles', type: 'string', mandatoryType: 'no', multiple: true, upsert: true },
    { name: 'sophistication', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'resource_level', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'primary_motivation', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'secondary_motivations', type: 'string', mandatoryType: 'no', multiple: true, upsert: true },
    { name: 'personal_motivations', type: 'string', mandatoryType: 'no', multiple: true, upsert: false },
  ],
  [ENTITY_TYPE_TOOL]: [
    aliases,
    iAliasedIds,
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'description', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
    {
      name: 'tool_types',
      type: 'string',
      mandatoryType: 'customizable',
      multiple: true,
      upsert: false,
      label: 'Tool types'
    },
    { name: 'tool_version', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
  ],
  [ENTITY_TYPE_VULNERABILITY]: [
    xOpenctiAliases,
    iAliasedIds,
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'description', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
    { name: 'x_opencti_base_score', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'x_opencti_base_severity', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'x_opencti_attack_vector', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'x_opencti_integrity_impact', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'x_opencti_availability_impact', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'x_opencti_confidentiality_impact', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
  ],
  [ENTITY_TYPE_INCIDENT]: [
    // Check Name, type, mandatory, multiple, upsert
    aliases,
    iAliasedIds,
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'description', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
    {
      name: 'incident_type',
      type: 'string',
      mandatoryType: 'customizable',
      multiple: false,
      upsert: true,
      label: 'Incident type'
    },
    { name: 'severity', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
    { name: 'source', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
    { name: 'first_seen', type: 'date', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'last_seen', type: 'date', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'objective', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
  ],
};
R.forEachObjIndexed((value, key) => schemaAttributesDefinition.registerAttributes(key as string, value), stixDomainObjectsAttributes);
