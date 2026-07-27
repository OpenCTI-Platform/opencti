import type { WidgetColumn, WidgetHost } from 'src/utils/widget/widget';
import useAttributes from '../../../utils/hooks/useAttributes';

const defaultWidgetColumns: Record<string, WidgetColumn[]> = {
  relationships: [
    { attribute: 'entity_type', label: 'Type' },
    { attribute: 'from_entity_type', label: 'Source type' },
    { attribute: 'from_relationship_type', label: 'Source name' },
    { attribute: 'to_entity_type', label: 'Target type' },
    { attribute: 'to_relationship_type', label: 'Target name' },
    { attribute: 'created', label: 'Original creation date' },
    { attribute: 'created_at', label: 'Platform creation date' },
    { attribute: 'createdBy' },
    { attribute: 'objectMarking' },
  ],
  common: [
    { attribute: 'entity_type', label: 'Type' },
    { attribute: 'name', label: 'Name' },
    { attribute: 'created', label: 'Original creation date' },
    { attribute: 'created_at', label: 'Platform creation date' },
    { attribute: 'modified', label: 'Modification date' },
    { attribute: 'createdBy' },
    { attribute: 'creators', label: 'Creators' },
    { attribute: 'x_opencti_workflow_id', label: 'Processing status' },
    { attribute: 'objectLabel' },
    { attribute: 'objectMarking' },
  ],
};

const fintelTemplateDefaultWidgetColumns = {
  entities: [
    { attribute: 'entity_type', label: 'Entity type' },
    { attribute: 'representative.main', label: 'Representative' },
    { attribute: 'created_at', label: 'Creation date' },
  ],
  relationships: [
    { attribute: 'relationship_type', label: 'Relationship type' },
    { attribute: 'from.representative.main', label: 'Source entity' },
    { attribute: 'to.representative.main', label: 'Target entity' },
    { attribute: 'created_at', label: 'Creation date' },
  ],
};

const availableWidgetColumns: Record<string, WidgetColumn[]> = {
  relationships: [
    ...defaultWidgetColumns.relationships,
    { attribute: 'start_time' },
    { attribute: 'stop_time' },
  ],
  common: [
    ...defaultWidgetColumns.common,
  ],
  Report: [
    { attribute: 'report_types', label: 'Report type' },
    { attribute: 'objectAssignee' },
    { attribute: 'objectParticipant' },
    { attribute: 'container_content', label: 'Content' },
  ],
  Grouping: [
    { attribute: 'context' },
    { attribute: 'container_content', label: 'Content' },
  ],
  'Malware-Analysis': [
    { attribute: 'product', label: 'Product' },
    { attribute: 'objectAssignee' },
  ],
  Note: [
    { attribute: 'note_types', label: 'Note type' },
  ],
  'Case-Incident': [
    { attribute: 'priority' },
    { attribute: 'severity', label: 'Severity' },
    { attribute: 'response_types', label: 'Response type' },
    { attribute: 'objectAssignee' },
    { attribute: 'objectParticipant' },
  ],
  'Case-Rfi': [
    { attribute: 'priority' },
    { attribute: 'severity', label: 'Severity' },
    { attribute: 'information_types', label: 'Request for information types' },
    { attribute: 'objectAssignee' },
    { attribute: 'objectParticipant' },
    { attribute: 'container_content', label: 'Content' },
  ],
  'Case-Rft': [
    { attribute: 'priority' },
    { attribute: 'severity', label: 'Severity' },
    { attribute: 'takedown_types', label: 'Request for takedown types' },
    { attribute: 'objectAssignee' },
    { attribute: 'objectParticipant' },
    { attribute: 'container_content', label: 'Content' },
  ],
  Task: [
    { attribute: 'due_date', label: 'Due date' },
    { attribute: 'objectAssignee' },
    { attribute: 'objectParticipant' },
  ],
  Incident: [
    { attribute: 'incident_type' },
    { attribute: 'severity', label: 'Severity' },
    { attribute: 'container_content', label: 'Content' },
  ],
  Indicator: [
    { attribute: 'pattern_type', label: 'Pattern type' },
    { attribute: 'valid_from', label: 'Valid from' },
    { attribute: 'valid_until', label: 'Valid until' },
    { attribute: 'x_opencti_score' },
  ],
  'Threat-Actor': [
    { attribute: 'threat_actor_types', label: 'Threat actor types' },
  ],
  'Threat-Actor-Individual': [
    { attribute: 'threat_actor_types', label: 'Threat actor types' },
  ],
  'Threat-Actor-Group': [
    { attribute: 'threat_actor_types', label: 'Threat actor types' },
  ],
  'Intrusion-Set': [
    { attribute: 'resource_level', label: 'Resource level' },
  ],
  Malware: [
    { attribute: 'malware_types', label: 'Malware type' },
  ],
  Channel: [
    { attribute: 'channel_types', label: 'Channel type' },
  ],
  Tool: [
    { attribute: 'tool_types', label: 'Tool types' },
  ],
  Vulnerability: [
    { attribute: 'x_opencti_cvss_base_score', label: 'CVSS3 - Score' },
    { attribute: 'x_opencti_cvss_base_severity', label: 'CVSS3 - Severity' },
    { attribute: 'x_opencti_cvss_v4_base_score', label: 'CVSS4 - Score' },
    { attribute: 'x_opencti_cvss_v4_base_severity', label: 'CVSS4 - Severity' },
    { attribute: 'x_opencti_cisa_kev', label: 'CISA - KEV' },
    { attribute: 'x_opencti_epss_score', label: 'EPSS Score' },
    { attribute: 'x_opencti_epss_percentile', label: 'EPSS Percentile' },
  ],
  'Attack-Pattern': [
    { attribute: 'x_mitre_id', label: 'External ID' },
  ],
  'Course-Of-Action': [
    { attribute: 'x_mitre_id', label: 'External ID' },
  ],
  Event: [
    { attribute: 'event_types', label: 'Event type' },
  ],
  Organization: [
    { attribute: 'x_opencti_organization_type', label: 'Organization type' },
    { attribute: 'x_opencti_score', label: 'Score' },
  ],
  DraftWorkspace: [
    { attribute: 'name', label: 'Name' },
    { attribute: 'draft_status', label: 'Processing status' },
    { attribute: 'workflowInstance', label: 'Workflow status' },
    { attribute: 'created_at', label: 'Platform creation date' },
    { attribute: 'creators', label: 'Creators' },
    { attribute: 'createdBy' },
    { attribute: 'objectAssignee' },
    { attribute: 'objectParticipant' },
  ],
};

// Additional columns, only available in the "custom-attributes" perspective.
const customAttributesTypeColumns: Record<string, WidgetColumn[]> = {
  Report: [
    { attribute: 'published', label: 'Publication date', attributeType: 'date' },
  ],
  'Malware-Analysis': [
    { attribute: 'result_name', label: 'Report name', attributeType: 'markdown' },
    { attribute: 'result', label: 'Maliciousness', attributeType: 'tag' },
    { attribute: 'version', label: 'Version of the product', attributeType: 'tag' },
    { attribute: 'configuration_version', label: 'Configuration version', attributeType: 'markdown' },
    { attribute: 'analysis_engine_version', label: 'Analysis engine version', attributeType: 'markdown' },
    { attribute: 'analysis_definition_version', label: 'Analysis definition version', attributeType: 'markdown' },
    { attribute: 'modules', label: 'Modules', attributeType: 'tag_list' },
    { attribute: 'submitted', label: 'Submission date', attributeType: 'date' },
    { attribute: 'analysis_started', label: 'Analysis started', attributeType: 'date' },
    { attribute: 'analysis_ended', label: 'Analysis ended', attributeType: 'date' },
  ],
  Incident: [
    { attribute: 'source', label: 'Source', attributeType: 'tag' },
    { attribute: 'objective', label: 'Objective', attributeType: 'markdown' },
    { attribute: 'first_seen', label: 'First seen', attributeType: 'date' },
    { attribute: 'last_seen', label: 'Last seen', attributeType: 'date' },
    { attribute: 'objectAssignee' },
    { attribute: 'objectParticipant' },
  ],
  Indicator: [
    { attribute: 'pattern', label: 'Indicator pattern' },
    { attribute: 'x_opencti_detection', label: 'Detection', attributeType: 'boolean' },
    { attribute: 'indicator_types', label: 'Indicator types', attributeType: 'open_vocab_list' },
    { attribute: 'x_opencti_main_observable_type', label: 'Main observable type', attributeType: 'open_vocab' },
    { attribute: 'x_mitre_platforms_indicator', label: 'Platforms', attributeType: 'tag_list' },
    { attribute: 'killChainPhases', label: 'Kill chain phases' },
  ],
  'Threat-Actor-Individual': [
    { attribute: 'first_seen', label: 'First seen', attributeType: 'date' },
    { attribute: 'last_seen', label: 'Last seen', attributeType: 'date' },
    { attribute: 'sophistication', label: 'Sophistication' },
    { attribute: 'resource_level', label: 'Resource level', attributeType: 'open_vocab' },
    { attribute: 'primary_motivation', label: 'Primary motivation', attributeType: 'open_vocab' },
    { attribute: 'secondary_motivations', label: 'Secondary motivations', attributeType: 'text_list' },
    { attribute: 'personal_motivations', label: 'Personal motivations', attributeType: 'text_list' },
    { attribute: 'goals', label: 'Goals', attributeType: 'text_list' },
    { attribute: 'roles', label: 'Roles', attributeType: 'text_list' },
    { attribute: 'eye_color', label: 'Eye color', attributeType: 'open_vocab' },
    { attribute: 'hair_color', label: 'Hair color', attributeType: 'open_vocab' },
    { attribute: 'height', label: 'Height' },
    { attribute: 'weight', label: 'Weight' },
    { attribute: 'date_of_birth', label: 'Date of birth', attributeType: 'date' },
    { attribute: 'gender', label: 'Gender', attributeType: 'open_vocab' },
    { attribute: 'marital_status', label: 'Marital status', attributeType: 'open_vocab' },
    { attribute: 'job_title', label: 'Job title' },
    { attribute: 'place_of_birth', label: 'Place of Birth' },
    { attribute: 'ethnicity', label: 'Ethnicity' },
  ],
  'Threat-Actor-Group': [
    { attribute: 'first_seen', label: 'First seen', attributeType: 'date' },
    { attribute: 'last_seen', label: 'Last seen', attributeType: 'date' },
    { attribute: 'sophistication', label: 'Sophistication' },
    { attribute: 'resource_level', label: 'Resource level', attributeType: 'open_vocab' },
    { attribute: 'primary_motivation', label: 'Primary motivation', attributeType: 'open_vocab' },
    { attribute: 'secondary_motivations', label: 'Secondary motivations', attributeType: 'text_list' },
    { attribute: 'goals', label: 'Goals', attributeType: 'text_list' },
    { attribute: 'roles', label: 'Roles', attributeType: 'text_list' },
  ],
  'Intrusion-Set': [
    { attribute: 'first_seen', label: 'First seen', attributeType: 'date' },
    { attribute: 'last_seen', label: 'Last seen', attributeType: 'date' },
    { attribute: 'primary_motivation', label: 'Primary motivation', attributeType: 'open_vocab' },
    { attribute: 'secondary_motivations', label: 'Secondary motivations', attributeType: 'text_list' },
    { attribute: 'goals', label: 'Goals', attributeType: 'text_list' },
  ],
  Malware: [
    { attribute: 'is_family', label: 'Is family', attributeType: 'boolean' },
    { attribute: 'first_seen', label: 'First seen', attributeType: 'date' },
    { attribute: 'last_seen', label: 'Last seen', attributeType: 'date' },
    { attribute: 'architecture_execution_envs', label: 'Architecture execution env.', attributeType: 'open_vocab_list' },
    { attribute: 'implementation_languages', label: 'Implementation languages', attributeType: 'open_vocab_list' },
    { attribute: 'capabilities', label: 'Capabilities', attributeType: 'open_vocab_list' },
    { attribute: 'killChainPhases', label: 'Kill chain phases' },
  ],
  Tool: [
    { attribute: 'tool_version', label: 'Tool version', attributeType: 'tag' },
    { attribute: 'killChainPhases', label: 'Kill chain phases' },
  ],
  Vulnerability: [
    { attribute: 'x_opencti_score', label: 'Score', attributeType: 'score' },
    { attribute: 'x_opencti_cwe', label: 'Associated CWE(s)', attributeType: 'text_list' },
    { attribute: 'x_opencti_first_seen_active', label: 'First seen active', attributeType: 'date' },
    // CVSS V2
    { attribute: 'x_opencti_cvss_v2_base_score', label: 'CVSS2 - Score', attributeType: 'cvss_score' },
    { attribute: 'x_opencti_cvss_v2_vector_string', label: 'CVSS2 - Vector', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_v2_access_vector', label: 'CVSS2 - Access Vector', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_v2_access_complexity', label: 'CVSS2 - Access Complexity', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_v2_authentication', label: 'CVSS2 - Authentication', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_v2_confidentiality_impact', label: 'CVSS2 - Confidentiality Impact', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_v2_integrity_impact', label: 'CVSS2 - Integrity Impact', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_v2_availability_impact', label: 'CVSS2 - Availability Impact', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_v2_exploitability', label: 'CVSS2 - Exploitability', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_v2_remediation_level', label: 'CVSS2 - Remediation Level', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_v2_report_confidence', label: 'CVSS2 - Report Confidence', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_v2_temporal_score', label: 'CVSS2 - Temporal Score', attributeType: 'cvss_score' },
    // CVSS V3
    { attribute: 'x_opencti_cvss_vector_string', label: 'CVSS3 - Vector', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_attack_vector', label: 'CVSS3 - Attack Vector', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_attack_complexity', label: 'CVSS3 - Attack Complexity', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_privileges_required', label: 'CVSS3 - Privileges Required', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_user_interaction', label: 'CVSS3 - User Interaction', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_scope', label: 'CVSS3 - Scope', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_confidentiality_impact', label: 'CVSS3 - Confidentiality Impact', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_integrity_impact', label: 'CVSS3 - Integrity Impact', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_availability_impact', label: 'CVSS3 - Availability Impact', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_exploit_code_maturity', label: 'CVSS3 - Exploit Code Maturity', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_remediation_level', label: 'CVSS3 - Remediation Level', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_report_confidence', label: 'CVSS3 - Report Confidence', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_temporal_score', label: 'CVSS3 - Temporal Score', attributeType: 'cvss_score' },
    // CVSS V4
    { attribute: 'x_opencti_cvss_v4_vector_string', label: 'CVSS4 - Vector', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_v4_attack_vector', label: 'CVSS4 - Attack Vector', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_v4_attack_complexity', label: 'CVSS4 - Attack Complexity', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_v4_attack_requirements', label: 'CVSS4 - Attack Requirements', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_v4_privileges_required', label: 'CVSS4 - Privileges Required', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_v4_user_interaction', label: 'CVSS4 - User Interaction', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_v4_confidentiality_impact_v', label: 'CVSS4 - VS Confidentiality Impact', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_v4_confidentiality_impact_s', label: 'CVSS4 - SS Confidentiality Impact', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_v4_integrity_impact_v', label: 'CVSS4 - VS Integrity Impact', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_v4_integrity_impact_s', label: 'CVSS4 - SS Integrity Impact', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_v4_availability_impact_v', label: 'CVSS4 - VS Availability Impact', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_v4_availability_impact_s', label: 'CVSS4 - SS Availability Impact', attributeType: 'tag' },
    { attribute: 'x_opencti_cvss_v4_exploit_maturity', label: 'CVSS4 - Exploit Maturity', attributeType: 'tag' },
  ],
  'Attack-Pattern': [
    { attribute: 'x_mitre_platforms_attack_pattern', label: 'Platforms', attributeType: 'tag_list' },
    { attribute: 'x_mitre_permissions_required', label: 'Required permissions', attributeType: 'tag_list' },
    { attribute: 'x_mitre_detection', label: 'Detection', attributeType: 'markdown' },
    { attribute: 'killChainPhases', label: 'Kill chain phases' },
  ],
  Event: [
    { attribute: 'start_time', label: 'Start time', attributeType: 'date' },
    { attribute: 'stop_time', label: 'Stop time', attributeType: 'date' },
  ],
  Organization: [
    { attribute: 'contact_information', label: 'Contact information', attributeType: 'markdown' },
  ],
  Campaign: [
    { attribute: 'objective', label: 'Objective', attributeType: 'markdown' },
    { attribute: 'first_seen', label: 'First seen', attributeType: 'date' },
    { attribute: 'last_seen', label: 'Last seen', attributeType: 'date' },
  ],
  Infrastructure: [
    { attribute: 'infrastructure_types', label: 'Infrastructure types', attributeType: 'open_vocab_list' },
    { attribute: 'first_seen', label: 'First seen', attributeType: 'date' },
    { attribute: 'last_seen', label: 'Last seen', attributeType: 'date' },
    { attribute: 'killChainPhases', label: 'Kill chain phases' },
  ],
  SecurityPlatform: [
    { attribute: 'security_platform_type', label: 'Security platform type', attributeType: 'tag' },
  ],
  System: [
    { attribute: 'contact_information', label: 'Contact information', attributeType: 'markdown' },
    { attribute: 'x_opencti_reliability', label: 'Reliability', attributeType: 'open_vocab' },
  ],
  Individual: [
    { attribute: 'contact_information', label: 'Contact information', attributeType: 'markdown' },
    { attribute: 'x_opencti_reliability', label: 'Reliability', attributeType: 'open_vocab' },
  ],
  Position: [
    { attribute: 'latitude', label: 'Latitude' },
    { attribute: 'longitude', label: 'Longitude' },
    { attribute: 'street_address', label: 'Street address' },
    { attribute: 'postal_code', label: 'Postal code' },
  ],
  'Stix-Cyber-Observable': [
    { attribute: 'observable_value', label: 'Value' },
    { attribute: 'x_opencti_score', label: 'Score', attributeType: 'score' },
    { attribute: 'x_opencti_description', label: 'Description', attributeType: 'markdown' },
    { attribute: 'entity_type', label: 'Observable type', attributeType: 'open_vocab' },
  ],
  Artifact: [
    { attribute: 'mime_type', label: 'MIME Type', attributeType: 'copy' },
    { attribute: 'x_opencti_additional_names', label: 'Additional Names', attributeType: 'copy' },
    { attribute: 'encryption_algorithm', label: 'Encryption Algorithm', attributeType: 'copy' },
    { attribute: 'decryption_key', label: 'Decryption Key', attributeType: 'copy' },
    { attribute: 'hash_md5', label: 'MD5' },
    { attribute: 'hash_sha1', label: 'SHA-1' },
    { attribute: 'hash_sha256', label: 'SHA-256' },
    { attribute: 'hash_sha512', label: 'SHA-512' },
    { attribute: 'url', label: 'URL', attributeType: 'copy' },
    { attribute: 'payload_bin', label: 'Payload', attributeType: 'copy' },
    { attribute: 'x_opencti_score', label: 'Score', attributeType: 'score' },
  ],
  'Administrative-Area': [
    { attribute: 'latitude', label: 'Latitude' },
    { attribute: 'longitude', label: 'Longitude' },
  ],
  City: [
    { attribute: 'latitude', label: 'Latitude' },
    { attribute: 'longitude', label: 'Longitude' },
  ],
  'Security-Coverage': [
    { attribute: 'objectCovered', label: 'Covered entity' },
    { attribute: 'coverage_valid_from', label: 'Valid from', attributeType: 'date' },
    { attribute: 'coverage_valid_to', label: 'Valid until', attributeType: 'date' },
    { attribute: 'coverage_last_result', label: 'Last result', attributeType: 'date' },
    { attribute: 'coverage_information', label: 'Detection' },
  ],
};

const customAttributesExtraColumns: WidgetColumn[] = [
  { attribute: 'description', label: 'Description', attributeType: 'markdown' },
  { attribute: 'revoked', label: 'Revoked', attributeType: 'boolean' },
  { attribute: 'confidence', label: 'Confidence' },
];

const EXCLUDED_COMMON_COLUMNS: Partial<Record<string, string[]>> = {
  'Malware-Analysis': ['name', 'description', 'modified', 'entity_type'],
  Indicator: ['name', 'entity_type'],
  'Stix-Cyber-Observable': ['entity_type', 'name', 'description', 'revoked', 'x_opencti_workflow_id', 'confidence'],
  Artifact: ['name', 'entity_type', 'revoked', 'x_opencti_workflow_id', 'confidence'],
  Campaign: ['entity_type'],
  'Attack-Pattern': ['entity_type'],
  Channel: ['entity_type'],
  City: ['entity_type'],
  Country: ['entity_type'],
  Event: ['entity_type'],
  Grouping: ['entity_type'],
  Incident: ['entity_type'],
  'Case-Incident': ['entity_type'],
  Individual: ['entity_type'],
  Infrastructure: ['entity_type'],
  'Intrusion-Set': ['entity_type'],
  Malware: ['entity_type'],
  Note: ['entity_type'],
  Narrative: ['entity_type'],
  Organization: ['entity_type'],
  Position: ['entity_type'],
  Region: ['entity_type'],
  Report: ['entity_type'],
  'Case-Rfi': ['entity_type'],
  'Case-Rft': ['entity_type'],
  Sector: ['entity_type'],
  'Security-Coverage': ['entity_type'],
  SecurityPlatform: ['entity_type'],
  System: ['entity_type'],
  Tool: ['entity_type'],
  'Threat-Actor-Group': ['entity_type'],
  'Threat-Actor-Individual': ['entity_type'],
  'Threat-Actor': ['entity_type'],
  Vulnerability: ['entity_type'],
  'Administrative-Area': ['entity_type'],
};

type WidgetEntityType = 'relationships' | 'entities';

export const getDefaultWidgetColumns = (type: WidgetEntityType, context?: WidgetHost): WidgetColumn[] => {
  if (context?.kind === 'fintelTemplate') {
    if (type === 'relationships') {
      return fintelTemplateDefaultWidgetColumns.relationships;
    }
    if (type === 'entities') {
      return fintelTemplateDefaultWidgetColumns.entities;
    }
  }
  if (type === 'relationships') {
    return defaultWidgetColumns.relationships;
  }
  if (type === 'entities') {
    return defaultWidgetColumns.common;
  }
  return [];
};

type MetricConf = {
  attribute: string;
  name: string;
};

export type MetricsColumn = {
  readonly entity_type: string;
  readonly metrics: readonly MetricConf[] | null | undefined;
};

export const getDefaultCustomAttributesColumns = (entityType?: string): WidgetColumn[] => {
  return getCustomAttributesColumns(entityType);
};

export const getCustomAttributesColumns = (entityType?: string): WidgetColumn[] => {
  if (entityType) {
    const excluded = EXCLUDED_COMMON_COLUMNS[entityType] ?? [];

    const baseColumns = [
      ...availableWidgetColumns.common,
      ...customAttributesExtraColumns,
    ].filter((col) => !excluded.includes(col.attribute ?? ''));

    if (availableWidgetColumns[entityType]) {
      baseColumns.push(...availableWidgetColumns[entityType]);
    }

    if (customAttributesTypeColumns[entityType]) {
      baseColumns.push(...customAttributesTypeColumns[entityType]);
    }

    return baseColumns;
  }

  return [
    ...availableWidgetColumns.common,
    ...customAttributesExtraColumns,
  ];
};

export const getWidgetColumns = (type: WidgetEntityType, entityType?: string, metrics?: readonly MetricsColumn[]): WidgetColumn[] => {
  const { containerTypes, aliasedTypes } = useAttributes();

  if (type === 'relationships') {
    return availableWidgetColumns.relationships;
  }

  if (type === 'entities') {
    if (entityType === 'DraftWorkspace') {
      return availableWidgetColumns.DraftWorkspace;
    }

    if (entityType) {
      const baseColumns = [...availableWidgetColumns.common];

      // Determine the correct aliases column to add based on the entityType
      if (!containerTypes.includes(entityType)) {
        const aliasesColumn = aliasedTypes.includes(entityType)
          ? { attribute: 'aliases', label: 'Aliases' }
          : { attribute: 'x_opencti_aliases', label: 'Aliases' };
        baseColumns.push(aliasesColumn);
      }

      if (availableWidgetColumns[entityType]) {
        baseColumns.push(...availableWidgetColumns[entityType]);
      }

      if (metrics) {
        const metricsForEntity = metrics.find((m) => m.entity_type === entityType.toLowerCase());
        if (metricsForEntity?.metrics) {
          const metricsColumns = metricsForEntity.metrics.map((metricConf) => ({
            attribute: metricConf.attribute,
            label: metricConf.name,
          }));
          baseColumns.push(...metricsColumns);
        }
      }

      return baseColumns;
    }

    return availableWidgetColumns.common;
  }

  return [];
};
