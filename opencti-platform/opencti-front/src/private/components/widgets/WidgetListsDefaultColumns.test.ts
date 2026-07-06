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

    it('does NOT return custom-attributes-only additions (e.g. published)', () => {
      const columns = getWidgetColumns('entities', 'Report');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).not.toContain('published');
    });

    it('keeps the legacy Report-specific columns (already part of availableWidgetColumns)', () => {
      const columns = getWidgetColumns('entities', 'Report');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).toContain('report_types');
      expect(attributes).toContain('objectAssignee');
      expect(attributes).toContain('objectParticipant');
      expect(attributes).toContain('container_content');
    });

    it('includes the common columns (list perspective must stay generic)', () => {
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
    it('does NOT return the custom-attributes-only additions', () => {
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

    it('keeps the legacy malware_types column (already part of availableWidgetColumns)', () => {
      const columns = getWidgetColumns('entities', 'Malware');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).toContain('malware_types');
    });

    it('still includes the aliases column since Malware is an aliased type', () => {
      const columns = getWidgetColumns('entities', 'Malware');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).toContain('aliases');
    });
  });

  describe('getWidgetColumns for Vulnerability', () => {
    it('does NOT leak the detailed custom-attributes-only CVSS columns', () => {
      const columns = getWidgetColumns('entities', 'Vulnerability');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).not.toContain('x_opencti_cvss_v2_score');
      expect(attributes).not.toContain('x_opencti_cvss_v2_vector_string');
      expect(attributes).not.toContain('x_opencti_cvss_temporal_score');
      expect(attributes).not.toContain('x_opencti_cvss_vector_string');
    });

    it('keeps the legacy base CVSS/EPSS columns (already part of availableWidgetColumns)', () => {
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
    it('DOES include the legacy entity-type-specific columns for Report', () => {
      const columns = getCustomAttributesColumns('Report');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).toContain('report_types');
      expect(attributes).toContain('objectAssignee');
      expect(attributes).toContain('objectParticipant');
    });

    it('DOES include the custom-attributes-only additions for Report', () => {
      const columns = getCustomAttributesColumns('Report');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).toContain('published');
    });

    it('DOES include both the legacy and the additional entity-type-specific columns for Malware', () => {
      const columns = getCustomAttributesColumns('Malware');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).toContain('malware_types'); // legacy (availableWidgetColumns)
      expect(attributes).toContain('is_family'); // addition (customAttributesTypeColumns)
      expect(attributes).toContain('killChainPhases'); // addition (customAttributesTypeColumns)
    });

    it('DOES include the shared custom-attributes-only extra columns', () => {
      const columns = getCustomAttributesColumns('Malware');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).toContain('description');
      expect(attributes).toContain('revoked');
      expect(attributes).toContain('confidence');
    });

    it('excludes entity_type, which is redundant on the entity detail view', () => {
      // Design choice: on the custom-attributes (entity detail) perspective, the entity type
      // is already evident from the page context, unlike the generic "list" perspective which
      // mixes several entity types and therefore needs an explicit Type column.
      const reportColumns = getCustomAttributesColumns('Report').map((c) => c.attribute);
      const malwareColumns = getCustomAttributesColumns('Malware').map((c) => c.attribute);
      expect(reportColumns).not.toContain('entity_type');
      expect(malwareColumns).not.toContain('entity_type');
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

  describe('list vs custom-attributes perspective separation (regression test for the original bug)', () => {
    it('getWidgetColumns and getCustomAttributesColumns return DIFFERENT column sets for Malware', () => {
      const listColumns = getWidgetColumns('entities', 'Malware').map((c) => c.attribute);
      const customColumns = getCustomAttributesColumns('Malware').map((c) => c.attribute);

      // entity_type is intentionally excluded from the custom-attributes perspective
      // (EXCLUDED_COMMON_COLUMNS), so the subset check must ignore it explicitly.
      const listColumnsRelevantToCustom = listColumns.filter((attr) => attr !== 'entity_type');
      listColumnsRelevantToCustom.forEach((attr) => expect(customColumns).toContain(attr));

      // but the custom-attributes perspective must have strictly more (richer) columns
      expect(customColumns.length).toBeGreaterThan(listColumns.length);
      expect(customColumns).toContain('is_family');
      expect(listColumns).not.toContain('is_family');
    });

    it('getWidgetColumns and getCustomAttributesColumns return DIFFERENT column sets for Report', () => {
      const listColumns = getWidgetColumns('entities', 'Report').map((c) => c.attribute);
      const customColumns = getCustomAttributesColumns('Report').map((c) => c.attribute);

      const listColumnsRelevantToCustom = listColumns.filter((attr) => attr !== 'entity_type');
      listColumnsRelevantToCustom.forEach((attr) => expect(customColumns).toContain(attr));

      expect(customColumns).toContain('published');
      expect(listColumns).not.toContain('published');
    });
  });
});
