import { describe, it, expect, vi } from 'vitest';

vi.mock('../../../utils/hooks/useAttributes', () => ({
  default: () => ({
    containerTypes: ['Report', 'Grouping', 'Note', 'Case-Incident', 'Case-Rfi', 'Case-Rft'],
    aliasedTypes: ['Threat-Actor-Group', 'Threat-Actor-Individual', 'Intrusion-Set', 'Campaign', 'Malware', 'Tool'],
  }),
}));

// TODO(DRAFT_WORKFLOW): remove this mock when the DRAFT_WORKFLOW flag is removed (see WidgetListsDefaultColumns.tsx).
vi.mock('../../../utils/hooks/useHelper', () => ({
  default: () => ({
    isFeatureEnable: () => true,
  }),
}));

import { getWidgetColumns, getDefaultWidgetColumns, getCustomAttributesColumns, getDefaultCustomAttributesColumns } from './WidgetListsDefaultColumns';

describe('WidgetListsDefaultColumns', () => {
  describe('getWidgetColumns for DraftWorkspace', () => {
    it('returns exactly 8 columns', () => {
      const columns = getWidgetColumns('entities', 'DraftWorkspace');
      expect(columns).toHaveLength(8);
    });

    it('includes workflowInstance column', () => {
      const columns = getWidgetColumns('entities', 'DraftWorkspace');
      const workflowCol = columns.find((c) => c.attribute === 'workflowInstance');
      expect(workflowCol).toBeDefined();
      expect(workflowCol?.label).toBe('Workflow status');
    });

    it('includes all expected DraftWorkspace columns', () => {
      const columns = getWidgetColumns('entities', 'DraftWorkspace');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).toContain('name');
      expect(attributes).toContain('draft_status');
      expect(attributes).toContain('creators');
      expect(attributes).toContain('createdBy');
      expect(attributes).toContain('objectAssignee');
      expect(attributes).toContain('objectParticipant');
      expect(attributes).toContain('created_at');
    });
  });

  describe('getWidgetColumns for Report', () => {
    it('does NOT return DraftWorkspace-specific columns', () => {
      const columns = getWidgetColumns('entities', 'Report');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).not.toContain('draft_status');
      expect(attributes).not.toContain('workflowInstance');
    });

    it('does NOT return Report-specific (custom-attributes only) columns', () => {
      const columns = getWidgetColumns('entities', 'Report');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).not.toContain('report_types');
      expect(attributes).not.toContain('published');
      expect(attributes).not.toContain('objectAssignee');
      expect(attributes).not.toContain('objectParticipant');
    });

    it('only returns the common columns (list perspective must stay generic)', () => {
      const columns = getWidgetColumns('entities', 'Report');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).toContain('entity_type');
      expect(attributes).toContain('name');
      expect(attributes).toContain('created');
      expect(attributes).toContain('created_at');
      expect(attributes).toContain('modified');
      expect(attributes).toContain('createdBy');
      expect(attributes).toContain('creators');
      expect(attributes).toContain('x_opencti_workflow_id');
      expect(attributes).toContain('objectLabel');
      expect(attributes).toContain('objectMarking');
    });
  });

  describe('getWidgetColumns for Malware', () => {
    it('does NOT return Malware-specific (custom-attributes only) columns', () => {
      const columns = getWidgetColumns('entities', 'Malware');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).not.toContain('malware_types');
      expect(attributes).not.toContain('is_family');
      expect(attributes).not.toContain('first_seen');
      expect(attributes).not.toContain('last_seen');
      expect(attributes).not.toContain('architecture_execution_envs');
      expect(attributes).not.toContain('implementation_languages');
      expect(attributes).not.toContain('capabilities');
      expect(attributes).not.toContain('killChainPhases');
    });

    it('still includes the aliases column since Malware is an aliased type', () => {
      const columns = getWidgetColumns('entities', 'Malware');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).toContain('aliases');
    });
  });

  describe('getWidgetColumns for Vulnerability', () => {
    it('does NOT leak any CVSS-related custom attribute columns', () => {
      const columns = getWidgetColumns('entities', 'Vulnerability');
      const attributes = columns.map((c) => c.attribute);
      const leaked = attributes.filter((a) => a?.startsWith('x_opencti_cvss'));
      expect(leaked).toHaveLength(0);
    });
  });

  describe('getDefaultWidgetColumns', () => {
    it('returns common columns for entities perspective', () => {
      const columns = getDefaultWidgetColumns('entities');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).toContain('entity_type');
      expect(attributes).toContain('name');
      expect(attributes).toContain('created_at');
      expect(attributes).not.toContain('draft_status');
      expect(attributes).not.toContain('workflowInstance');
    });
  });

  describe('getCustomAttributesColumns (custom-attributes perspective)', () => {
    it('DOES include the entity-type-specific columns for Report', () => {
      const columns = getCustomAttributesColumns('Report');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).toContain('report_types');
      expect(attributes).toContain('published');
      expect(attributes).toContain('objectAssignee');
      expect(attributes).toContain('objectParticipant');
    });

    it('DOES include the entity-type-specific columns for Malware', () => {
      const columns = getCustomAttributesColumns('Malware');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).toContain('malware_types');
      expect(attributes).toContain('is_family');
      expect(attributes).toContain('killChainPhases');
    });

    it('DOES include the shared custom-attributes-only extra columns', () => {
      const columns = getCustomAttributesColumns('Malware');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).toContain('description');
      expect(attributes).toContain('revoked');
      expect(attributes).toContain('confidence');
    });

    it('respects EXCLUDED_COMMON_COLUMNS for Indicator (no name / entity_type)', () => {
      const columns = getCustomAttributesColumns('Indicator');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).not.toContain('name');
      expect(attributes).not.toContain('entity_type');
      expect(attributes).toContain('pattern');
    });
  });

  describe('getDefaultCustomAttributesColumns', () => {
    it('returns a default set that includes type-specific columns for Report', () => {
      const columns = getDefaultCustomAttributesColumns('Report');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).toContain('report_types');
    });
  });
});
