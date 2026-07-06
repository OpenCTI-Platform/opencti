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

    it('DOES return the legacy, lightweight Report columns (part of availableWidgetColumns, list perspective)', () => {
      const columns = getWidgetColumns('entities', 'Report');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).toContain('report_types');
      expect(attributes).toContain('objectAssignee');
      expect(attributes).toContain('objectParticipant');
      expect(attributes).toContain('container_content');
    });

    it('does NOT return the richer, custom-attributes-only Report columns', () => {
      const columns = getWidgetColumns('entities', 'Report');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).not.toContain('published');
    });

    it('returns the common columns plus the Report-specific ones (list perspective stays lightweight, not empty)', () => {
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
    it('DOES return the legacy, lightweight Malware column (malware_types)', () => {
      const columns = getWidgetColumns('entities', 'Malware');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).toContain('malware_types');
    });

    it('does NOT leak the richer, custom-attributes-only Malware columns (regression test for the original bug)', () => {
      const columns = getWidgetColumns('entities', 'Malware');
      const attributes = columns.map((c) => c.attribute);
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
    it('DOES return the legacy, lightweight Vulnerability columns', () => {
      const columns = getWidgetColumns('entities', 'Vulnerability');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).toContain('x_opencti_cvss_base_score');
      expect(attributes).toContain('x_opencti_cvss_base_severity');
      expect(attributes).toContain('x_opencti_cvss_v4_base_score');
      expect(attributes).toContain('x_opencti_cvss_v4_base_severity');
      expect(attributes).toContain('x_opencti_cisa_kev');
      expect(attributes).toContain('x_opencti_epss_score');
      expect(attributes).toContain('x_opencti_epss_percentile');
    });

    it('does NOT leak the detailed CVSS v2/v3/v4 custom-attributes-only columns', () => {
      const columns = getWidgetColumns('entities', 'Vulnerability');
      const attributes = columns.map((c) => c.attribute ?? '');
      const leaked = attributes.filter((a) => a.includes('_v2_') || a.includes('vector_string') || a.includes('temporal_score') || a.includes('attack_vector') || a.includes('attack_complexity'));
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
    it('includes both the legacy columns (from availableWidgetColumns) and the extra ones (from customAttributesTypeColumns) for Report', () => {
      const columns = getCustomAttributesColumns('Report');
      const attributes = columns.map((c) => c.attribute);
      // legacy / shared with the list perspective
      expect(attributes).toContain('report_types');
      expect(attributes).toContain('objectAssignee');
      expect(attributes).toContain('objectParticipant');
      expect(attributes).toContain('container_content');
      // custom-attributes-only addition
      expect(attributes).toContain('published');
    });

    it('includes both the legacy column and the extra rich columns for Malware', () => {
      const columns = getCustomAttributesColumns('Malware');
      const attributes = columns.map((c) => c.attribute);
      // legacy / shared with the list perspective
      expect(attributes).toContain('malware_types');
      // custom-attributes-only additions
      expect(attributes).toContain('is_family');
      expect(attributes).toContain('first_seen');
      expect(attributes).toContain('last_seen');
      expect(attributes).toContain('architecture_execution_envs');
      expect(attributes).toContain('implementation_languages');
      expect(attributes).toContain('capabilities');
      expect(attributes).toContain('killChainPhases');
    });

    it('DOES include the shared custom-attributes-only extra columns (description, revoked, confidence)', () => {
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

    it('exposes richer Vulnerability columns than the list perspective (CVSS v2 detail included)', () => {
      const columns = getCustomAttributesColumns('Vulnerability');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).toContain('x_opencti_cvss_base_score');
      expect(attributes).toContain('x_opencti_cvss_v2_base_score');
      expect(attributes).toContain('x_opencti_cvss_vector_string');
    });
  });

  describe('getDefaultCustomAttributesColumns', () => {
    it('returns a default set that includes type-specific columns for Report', () => {
      const columns = getDefaultCustomAttributesColumns('Report');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).toContain('report_types');
      expect(attributes).toContain('published');
    });
  });

  describe('list vs custom-attributes perspective separation (regression test for the original bug)', () => {
    it('getWidgetColumns and getCustomAttributesColumns return DIFFERENT column sets for Malware', () => {
      const listColumns = getWidgetColumns('entities', 'Malware').map((c) => c.attribute);
      const customColumns = getCustomAttributesColumns('Malware').map((c) => c.attribute);

      // the list perspective must stay a strict subset of the custom-attributes perspective
      listColumns.forEach((attr) => expect(customColumns).toContain(attr));

      // but the custom-attributes perspective must have strictly more columns
      expect(customColumns.length).toBeGreaterThan(listColumns.length);
      expect(customColumns).toContain('capabilities');
      expect(listColumns).not.toContain('capabilities');
    });

    it('getWidgetColumns and getCustomAttributesColumns return DIFFERENT column sets for Report', () => {
      const listColumns = getWidgetColumns('entities', 'Report').map((c) => c.attribute);
      const customColumns = getCustomAttributesColumns('Report').map((c) => c.attribute);

      listColumns.forEach((attr) => expect(customColumns).toContain(attr));
      expect(customColumns).toContain('published');
      expect(listColumns).not.toContain('published');
    });
  });
});
