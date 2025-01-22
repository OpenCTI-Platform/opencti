import type { WidgetColumn } from '../../../utils/widget/widget';

export const defaultWidgetColumns: Record<string, WidgetColumn[]> = {
  relationships: [
    { attribute: 'entity_type', label: 'Type' },
    { attribute: 'from_entity_type', label: 'Source type' },
    { attribute: 'from_relationship_type', label: 'Source name' },
    { attribute: 'to_entity_type', label: 'Target type' },
    { attribute: 'to_relationship_type', label: 'Target name' },
    { attribute: 'created_at', label: 'Platform creation date' },
    { attribute: 'createdBy' },
    { attribute: 'objectMarking' },
  ],
  common: [
    { attribute: 'entity_type', label: 'Type' },
    { attribute: 'name', label: 'Name' },
    { attribute: 'created_at', label: 'Platform creation date' },
    { attribute: 'updated_at', label: 'Modification date' },
    { attribute: 'createdBy' },
    { attribute: 'creator', label: 'Creators' },
    { attribute: 'x_opencti_workflow_id' },
    { attribute: 'objectLabel' },
    { attribute: 'x_opencti_aliases', label: 'Aliases' },
    { attribute: 'objectMarking' },
  ],
};

const commonWidgetColumns: Record<string, WidgetColumn[]> = {
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
  ],
  Grouping: [
    { attribute: 'context' },
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
    { attribute: 'response_types', label: 'Incident type' },
    { attribute: 'objectAssignee' },
    { attribute: 'objectParticipant' },
  ],
  'Case-Rfi': [
    { attribute: 'priority' },
    { attribute: 'severity', label: 'Severity' },
    { attribute: 'response_types', label: 'Incident type' },
    { attribute: 'objectAssignee' },
    { attribute: 'objectParticipant' },
  ],
  'Case-Rft': [
    { attribute: 'priority' },
    { attribute: 'severity', label: 'Severity' },
    { attribute: 'response_types', label: 'Incident type' },
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
    { attribute: 'malware_types' },
  ],
  Channel: [
    { attribute: 'channel_types' },
  ],
  Tool: [
    { attribute: 'tool_types', label: 'Tool types' },
  ],
  Vulnerability: [
    { attribute: 'x_opencti_cvss_base_score', label: 'CVSS3 - Score' },
    { attribute: 'x_opencti_cvss_base_severity', label: 'CVSS3 - Severity' },
    { attribute: 'x_opencti_cisa_kev', label: 'CISA - KEV' },
    { attribute: 'x_opencti_epss_score', label: 'EPSS Score' },
    { attribute: 'x_opencti_epss_percentile', label: 'EPSS Percentile' },
  ],
  // ttp ?
  'Course-Of-Action': [
    { attribute: 'x_mitre_id', label: 'External ID' },
  ],
  Event: [
    { attribute: 'event_types' },
  ],
  Organization: [
    { attribute: 'x_opencti_organization_type' },
  ],
};

export const getDefaultWidgetColumns = (type: string): WidgetColumn[] => {
  if (type === 'relationships') {
    return defaultWidgetColumns.relationships;
  }
  if (type === 'entities') {
    return defaultWidgetColumns.common;
  }
  return [];
};

export const getWidgetColumns = (type: string, entityType?: string): WidgetColumn[] => {
  if (type === 'relationships') {
    return commonWidgetColumns.relationships;
  }
  if (type === 'entities') {
    if (entityType && commonWidgetColumns[entityType]) {
      return [...commonWidgetColumns.common, ...commonWidgetColumns[entityType]];
    }
    return commonWidgetColumns.common;
  }
  return [];
};
