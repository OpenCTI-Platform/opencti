import type { WidgetColumn, WidgetHost } from 'src/utils/widget/widget';
import useAttributes from '../../../utils/hooks/useAttributes';
import useHelper from '../../../utils/hooks/useHelper';

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
  Campaign: [
    { attribute: 'objective', label: 'Objective' },
    { attribute: 'first_seen', label: 'First seen' },
    { attribute: 'last_seen', label: 'Last seen' },
  ],
  'Malware-Analysis': [
    { attribute: 'product', label: 'Product' },
    { attribute: 'result_name', label: 'Result name' },
    { attribute: 'result', label: 'Maliciousness' },
    { attribute: 'version', label: 'Version of the product' },
    { attribute: 'configuration_version', label: 'Configuration version' },
    { attribute: 'analysis_engine_version', label: 'Analysis engine version' },
    { attribute: 'analysis_definition_version', label: 'Analysis definition version' },
    { attribute: 'modules', label: 'Modules' },
    { attribute: 'submitted', label: 'Submission date' },
    { attribute: 'analysis_started', label: 'Analysis started' },
    { attribute: 'analysis_ended', label: 'Analysis ended' },
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
  ],
  'Case-Rft': [
    { attribute: 'priority' },
    { attribute: 'severity', label: 'Severity' },
    { attribute: 'takedown_types', label: 'Request for takedown types' },
    { attribute: 'objectAssignee' },
    { attribute: 'objectParticipant' },
  ],
  Task: [
    { attribute: 'due_date', label: 'Due date' },
    { attribute: 'objectAssignee' },
    { attribute: 'objectParticipant' },
  ],
  Incident: [
    { attribute: 'incident_type' },
    { attribute: 'severity', label: 'Severity' },
    { attribute: 'source', label: 'Source' },
    { attribute: 'objective', label: 'Objective' },
    { attribute: 'first_seen', label: 'First seen' },
    { attribute: 'last_seen', label: 'Last seen' },
  ],
  Indicator: [
    { attribute: 'pattern', label: 'Indicator pattern' },
    { attribute: 'valid_from', label: 'Valid from' },
    { attribute: 'valid_until', label: 'Valid until' },
    { attribute: 'x_opencti_score', label: 'Score' },
    { attribute: 'x_opencti_detection', label: 'Detection' },
    { attribute: 'indicator_types', label: 'Indicator types' },
    { attribute: 'x_opencti_main_observable_type', label: 'Main observable type' },
    { attribute: 'x_mitre_platforms_indicator', label: 'Platforms' },
    { attribute: 'killChainPhases', label: 'Kill chain phases' },
  ],
  Infrastructure: [
    { attribute: 'infrastructure_types', label: 'Infrastructure types' },
    { attribute: 'first_seen', label: 'First seen' },
    { attribute: 'last_seen', label: 'Last seen' },
    { attribute: 'killChainPhases', label: 'Kill chain phases' },
  ],
  'Threat-Actor': [
    { attribute: 'threat_actor_types', label: 'Threat actor types' },
  ],
  'Threat-Actor-Individual': [
    { attribute: 'threat_actor_types', label: 'Threat actor types' },
    { attribute: 'first_seen', label: 'First seen' },
    { attribute: 'last_seen', label: 'Last seen' },
    { attribute: 'sophistication', label: 'Sophistication' },
    { attribute: 'resource_level', label: 'Resource level' },
    { attribute: 'primary_motivation', label: 'Primary motivation' },
    { attribute: 'secondary_motivations', label: 'Secondary motivations' },
    { attribute: 'personal_motivations', label: 'Personal motivations' },
    { attribute: 'goals', label: 'Goals' },
    { attribute: 'roles', label: 'Roles' },
    { attribute: 'eye_color', label: 'Eye color' },
    { attribute: 'hair_color', label: 'Hair color' },
    { attribute: 'height', label: 'Height' },
    { attribute: 'weight', label: 'Weight' },
    { attribute: 'date_of_birth', label: 'Date of birth' },
    { attribute: 'gender', label: 'Gender' },
    { attribute: 'marital_status', label: 'Marital status' },
    { attribute: 'job_title', label: 'Job title' },
    { attribute: 'place_of_birth', label: 'Place of Birth' },
    { attribute: 'ethnicity', label: 'Ethnicity' },
  ],
  'Threat-Actor-Group': [
    { attribute: 'threat_actor_types', label: 'Threat actor types' },
    { attribute: 'first_seen', label: 'First seen' },
    { attribute: 'last_seen', label: 'Last seen' },
    { attribute: 'sophistication', label: 'Sophistication' },
    { attribute: 'resource_level', label: 'Resource level' },
    { attribute: 'primary_motivation', label: 'Primary motivation' },
    { attribute: 'secondary_motivations', label: 'Secondary motivations' },
    { attribute: 'goals', label: 'Goals' },
    { attribute: 'roles', label: 'Roles' },
  ],
  'Intrusion-Set': [
    { attribute: 'first_seen', label: 'First seen' },
    { attribute: 'last_seen', label: 'Last seen' },
    { attribute: 'resource_level', label: 'Resource level' },
    { attribute: 'primary_motivation', label: 'Primary motivation' },
    { attribute: 'secondary_motivations', label: 'Secondary motivations' },
    { attribute: 'goals', label: 'Goals' },
  ],
  Malware: [
    { attribute: 'malware_types', label: 'Malware types' },
    { attribute: 'is_family', label: 'Is family' },
    { attribute: 'first_seen', label: 'First seen' },
    { attribute: 'last_seen', label: 'Last seen' },
    { attribute: 'architecture_execution_envs', label: 'Architecture execution env.' },
    { attribute: 'implementation_languages', label: 'Implementation languages' },
    { attribute: 'capabilities', label: 'Capabilities' },
    { attribute: 'killChainPhases', label: 'Kill chain phases' },
  ],
  Channel: [
    { attribute: 'channel_types', label: 'Channel type' },
  ],
  Tool: [
    { attribute: 'tool_types', label: 'Tool types' },
    { attribute: 'tool_version', label: 'Tool version' },
    { attribute: 'killChainPhases', label: 'Kill chain phases' },
  ],
  Vulnerability: [
    { attribute: 'x_opencti_cvss_base_score', label: 'CVSS3 - Score' },
    { attribute: 'x_opencti_cvss_base_severity', label: 'CVSS3 - Severity' },
    { attribute: 'x_opencti_cvss_v4_base_score', label: 'CVSS4 - Score' },
    { attribute: 'x_opencti_cvss_v4_base_severity', label: 'CVSS4 - Severity' },
    { attribute: 'x_opencti_cisa_kev', label: 'CISA - KEV' },
    { attribute: 'x_opencti_epss_score', label: 'EPSS Score' },
    { attribute: 'x_opencti_epss_percentile', label: 'EPSS Percentile' },
    { attribute: 'x_opencti_score', label: 'Score' },
    { attribute: 'x_opencti_cwe', label: 'Associated CWE(s)' },
    { attribute: 'x_opencti_first_seen_active', label: 'First seen active' },
    // CVSS V2
    { attribute: 'x_opencti_cvss_v2_base_score', label: 'CVSS2 - Score' },
    { attribute: 'x_opencti_cvss_v2_vector_string', label: 'CVSS2 - Vector' },
    { attribute: 'x_opencti_cvss_v2_access_vector', label: 'CVSS2 - Access Vector' },
    { attribute: 'x_opencti_cvss_v2_access_complexity', label: 'CVSS2 - Access Complexity' },
    { attribute: 'x_opencti_cvss_v2_authentication', label: 'CVSS2 - Authentication' },
    { attribute: 'x_opencti_cvss_v2_confidentiality_impact', label: 'CVSS2 - Confidentiality Impact' },
    { attribute: 'x_opencti_cvss_v2_integrity_impact', label: 'CVSS2 - Integrity Impact' },
    { attribute: 'x_opencti_cvss_v2_availability_impact', label: 'CVSS2 - Availability Impact' },
    { attribute: 'x_opencti_cvss_v2_exploitability', label: 'CVSS2 - Exploitability' },
    { attribute: 'x_opencti_cvss_v2_remediation_level', label: 'CVSS2 - Remediation Level' },
    { attribute: 'x_opencti_cvss_v2_report_confidence', label: 'CVSS2 - Report Confidence' },
    { attribute: 'x_opencti_cvss_v2_temporal_score', label: 'CVSS2 - Temporal Score' },
    // CVSS V3
    { attribute: 'x_opencti_cvss_vector_string', label: 'CVSS3 - Vector' },
    { attribute: 'x_opencti_cvss_attack_vector', label: 'CVSS3 - Attack Vector' },
    { attribute: 'x_opencti_cvss_attack_complexity', label: 'CVSS3 - Attack Complexity' },
    { attribute: 'x_opencti_cvss_privileges_required', label: 'CVSS3 - Privileges Required' },
    { attribute: 'x_opencti_cvss_user_interaction', label: 'CVSS3 - User Interaction' },
    { attribute: 'x_opencti_cvss_scope', label: 'CVSS3 - Scope' },
    { attribute: 'x_opencti_cvss_confidentiality_impact', label: 'CVSS3 - Confidentiality Impact' },
    { attribute: 'x_opencti_cvss_integrity_impact', label: 'CVSS3 - Integrity Impact' },
    { attribute: 'x_opencti_cvss_availability_impact', label: 'CVSS3 - Availability Impact' },
    { attribute: 'x_opencti_cvss_exploit_code_maturity', label: 'CVSS3 - Exploit Code Maturity' },
    { attribute: 'x_opencti_cvss_remediation_level', label: 'CVSS3 - Remediation Level' },
    { attribute: 'x_opencti_cvss_report_confidence', label: 'CVSS3 - Report Confidence' },
    { attribute: 'x_opencti_cvss_temporal_score', label: 'CVSS3 - Temporal Score' },
    // CVSS V4
    { attribute: 'x_opencti_cvss_v4_vector_string', label: 'CVSS4 - Vector' },
    { attribute: 'x_opencti_cvss_v4_attack_vector', label: 'CVSS4 - Attack Vector' },
    { attribute: 'x_opencti_cvss_v4_attack_complexity', label: 'CVSS4 - Attack Complexity' },
    { attribute: 'x_opencti_cvss_v4_attack_requirements', label: 'CVSS4 - Attack Requirements' },
    { attribute: 'x_opencti_cvss_v4_privileges_required', label: 'CVSS4 - Privileges Required' },
    { attribute: 'x_opencti_cvss_v4_user_interaction', label: 'CVSS4 - User Interaction' },
    { attribute: 'x_opencti_cvss_v4_confidentiality_impact_v', label: 'CVSS4 - VS Confidentiality Impact' },
    { attribute: 'x_opencti_cvss_v4_confidentiality_impact_s', label: 'CVSS4 - SS Confidentiality Impact' },
    { attribute: 'x_opencti_cvss_v4_integrity_impact_v', label: 'CVSS4 - VS Integrity Impact' },
    { attribute: 'x_opencti_cvss_v4_integrity_impact_s', label: 'CVSS4 - SS Integrity Impact' },
    { attribute: 'x_opencti_cvss_v4_availability_impact_v', label: 'CVSS4 - VS Availability Impact' },
    { attribute: 'x_opencti_cvss_v4_availability_impact_s', label: 'CVSS4 - SS Availability Impact' },
    { attribute: 'x_opencti_cvss_v4_exploit_maturity', label: 'CVSS4 - Exploit Maturity' },
  ],
  'Attack-Pattern': [
    { attribute: 'x_mitre_id', label: 'External ID' },
    { attribute: 'x_mitre_platforms_attack_pattern', label: 'Platforms' },
    { attribute: 'x_mitre_permissions_required', label: 'Required permissions' },
    { attribute: 'x_mitre_detection', label: 'Detection' },
    { attribute: 'killChainPhases', label: 'Kill chain phases' },
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
    { attribute: 'contact_information', label: 'Contact information' },
  ],
  SecurityPlatform: [
    { attribute: 'security_platform_type', label: 'Security platform type' },
  ],
  System: [
    { attribute: 'contact_information', label: 'Contact information' },
  ],
  Individual: [
    { attribute: 'contact_information', label: 'Contact information' },
  ],
  Position: [
    { attribute: 'latitude', label: 'Latitude' },
    { attribute: 'longitude', label: 'Longitude' },
    { attribute: 'street_address', label: 'Street address' },
    { attribute: 'postal_code', label: 'Postal code' },
  ],
  'Stix-Cyber-Observable': [
    { attribute: 'observable_value', label: 'Value' },
  ],
  Artifact: [
    { attribute: 'mime_type', label: 'MIME Type' },
    { attribute: 'x_opencti_additional_names', label: 'Additional Names' },
    { attribute: 'encryption_algorithm', label: 'Encryption Algorithm' },
    { attribute: 'decryption_key', label: 'Decryption Key' },
    { attribute: 'hash_md5', label: 'MD5' },
    { attribute: 'hash_sha1', label: 'SHA-1' },
    { attribute: 'hash_sha256', label: 'SHA-256' },
    { attribute: 'hash_sha512', label: 'SHA-512' },
    { attribute: 'url', label: 'URL' },
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

const customAttributesExtraColumns: WidgetColumn[] = [
  { attribute: 'description', label: 'Description' },
  { attribute: 'revoked', label: 'Revoked' },
  { attribute: 'confidence', label: 'Confidence' },
];

const EXCLUDED_COMMON_COLUMNS: Partial<Record<string, string[]>> = {
  'Malware-Analysis': ['name', 'description', 'modified'],
  Indicator: ['name'],
  'Stix-Cyber-Observable': ['name'],
  Artifact: ['name'],
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

    return baseColumns;
  }

  return [
    ...availableWidgetColumns.common,
    ...customAttributesExtraColumns,
  ];
};

export const getWidgetColumns = (type: WidgetEntityType, entityType?: string, metrics?: readonly MetricsColumn[]): WidgetColumn[] => {
  const { containerTypes, aliasedTypes } = useAttributes();
  // TODO(DRAFT_WORKFLOW): remove useHelper and isDraftWorkflowEnabled when the DRAFT_WORKFLOW flag is removed.
  // Also remove the corresponding vi.mock('useHelper') in WidgetListsDefaultColumns.test.ts.
  const { isFeatureEnable } = useHelper();
  const isDraftWorkflowEnabled = isFeatureEnable('DRAFT_WORKFLOW');

  if (type === 'relationships') {
    return availableWidgetColumns.relationships;
  }

  if (type === 'entities') {
    if (entityType === 'DraftWorkspace') {
      const draftColumns = availableWidgetColumns.DraftWorkspace;
      return isDraftWorkflowEnabled ? draftColumns : draftColumns.filter((c) => c.attribute !== 'workflowInstance');
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
