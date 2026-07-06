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

    it('DOES include the legacy Report columns already present in availableWidgetColumns', () => {
      // These are NOT custom-attributes-only additions: they were already part of the
      // historical 'availableWidgetColumns.Report' entry, so getWidgetColumns must keep them.
      const columns = getWidgetColumns('entities', 'Report');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).toContain('report_types');
      expect(attributes).toContain('objectAssignee');
      expect(attributes).toContain('objectParticipant');
    });

    it('does NOT return Report-specific (custom-attributes-only addition) columns', () => {
      const columns = getWidgetColumns('entities', 'Report');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).not.toContain('published');
    });

    it('only returns the common + legacy columns (list perspective must stay generic)', () => {
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
    it('DOES include the legacy Malware column already present in availableWidgetColumns', () => {
      const columns = getWidgetColumns('entities', 'Malware');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).toContain('malware_types');
    });

    it('does NOT return Malware-specific (custom-attributes-only addition) columns', () => {
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
    it('does NOT leak the detailed CVSS custom-attributes-only columns', () => {
      const columns = getWidgetColumns('entities', 'Vulnerability');
      const attributes = columns.map((c) => c.attribute);
      const leaked = attributes.filter((a) => a?.startsWith('x_opencti_cvss') && !a?.endsWith('_score') && !a?.endsWith('_severity'));
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
    it('DOES include the legacy entity-type-specific columns for Report (from availableWidgetColumns)', () => {
      const columns = getCustomAttributesColumns('Report');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).toContain('report_types');
      expect(attributes).toContain('objectAssignee');
      expect(attributes).toContain('objectParticipant');
    });

    it('DOES include the custom-attributes-only addition for Report (from customAttributesTypeColumns)', () => {
      const columns = getCustomAttributesColumns('Report');
      const attributes = columns.map((c) => c.attribute);
      expect(attributes).toContain('published');
    });

    it('DOES include both the legacy and the additional columns for Malware (merge of both arrays)', () => {
      const columns = getCustomAttributesColumns('Malware');
      const attributes = columns.map((c) => c.attribute);
      // legacy, from availableWidgetColumns
      expect(attributes).toContain('malware_types');
      // additions, from customAttributesTypeColumns
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

  describe('list vs custom-attributes perspective separation (regression test for the original bug)', () => {
    it('excludes entity_type, which is redundant on the entity detail view (EXCLUDED_COMMON_COLUMNS)', () => {
      const customColumns = getCustomAttributesColumns('Malware').map((c) => c.attribute);
      expect(customColumns).not.toContain('entity_type');
    });

    it('excludes the dynamically-computed aliases column, which is only relevant to the list table view', () => {
      // `aliases` / `x_opencti_aliases` are computed on the fly by getWidgetColumns based on
      // `aliasedTypes`, to let the generic list table show a name/alias column across mixed
      // entity types. On the custom-attributes (entity detail) perspective the type is already
      // known and aliases are shown elsewhere in the entity's own UI, so they're intentionally
      // not part of getCustomAttributesColumns.
      const customColumns = getCustomAttributesColumns('Malware').map((c) => c.attribute);
      expect(customColumns).not.toContain('aliases');
      expect(customColumns).not.toContain('x_opencti_aliases');
    });

    it('getWidgetColumns and getCustomAttributesColumns return DIFFERENT column sets for Malware', () => {
      const listColumns = getWidgetColumns('entities', 'Malware').map((c) => c.attribute);
      const customColumns = getCustomAttributesColumns('Malware').map((c) => c.attribute);

      // entity_type and aliases are legitimately list-only (see dedicated tests above), so the
      // subset check must ignore them.
      const listColumnsRelevantToCustom = listColumns.filter(
        (attr) => attr !== 'entity_type' && attr !== 'aliases' && attr !== 'x_opencti_aliases',
      );
      listColumnsRelevantToCustom.forEach((attr) => expect(customColumns).toContain(attr));

      // but the custom-attributes perspective must have strictly more columns (the additions)
      expect(customColumns.length).toBeGreaterThan(listColumns.length);
      expect(customColumns).toContain('is_family');
      expect(listColumns).not.toContain('is_family');
    });

    it('getWidgetColumns and getCustomAttributesColumns return DIFFERENT column sets for Report', () => {
      const listColumns = getWidgetColumns('entities', 'Report').map((c) => c.attribute);
      const customColumns = getCustomAttributesColumns('Report').map((c) => c.attribute);

      const listColumnsRelevantToCustom = listColumns.filter(
        (attr) => attr !== 'entity_type' && attr !== 'aliases' && attr !== 'x_opencti_aliases',
      );
      listColumnsRelevantToCustom.forEach((attr) => expect(customColumns).toContain(attr));

      expect(customColumns).toContain('published');
      expect(listColumns).not.toContain('published');
    });
  });
});
