import type { WidgetColumn, WidgetContext } from '../../../utils/widget/widget';
import useAttributes from '../../../utils/hooks/useAttributes';

const defaultWidgetColumns: Record<string, WidgetColumn[]> = {
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
    { attribute: 'modified', label: 'Modification date' },
    { attribute: 'createdBy' },
    { attribute: 'creators', label: 'Creators' },
    { attribute: 'x_opencti_workflow_id' },
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
    { attribute: 'response_types', label: 'Response type' },
    { attribute: 'objectAssignee' },
    { attribute: 'objectParticipant' },
  ],
  'Case-Rfi': [
    { attribute: 'priority' },
    { attribute: 'severity', label: 'Severity' },
    { attribute: 'information_types', label: 'Information type' },
    { attribute: 'objectAssignee' },
    { attribute: 'objectParticipant' },
  ],
  'Case-Rft': [
    { attribute: 'priority' },
    { attribute: 'severity', label: 'Severity' },
    { attribute: 'takedown_types', label: 'Takedown type' },
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
  ],
};

type WidgetEntityType = 'relationships' | 'entities';

export const getDefaultWidgetColumns = (type: WidgetEntityType, context?: WidgetContext): WidgetColumn[] => {
  if (context && context === 'fintelTemplate') {
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

export const getWidgetColumns = (type: WidgetEntityType, entityType?: string): WidgetColumn[] => {
  const { containerTypes, aliasedTypes } = useAttributes();

  if (type === 'relationships') {
    return availableWidgetColumns.relationships;
  }

  if (type === 'entities') {
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
        return [...baseColumns, ...availableWidgetColumns[entityType]];
      }
      return baseColumns;
    }

    return availableWidgetColumns.common;
  }

  return [];
};
