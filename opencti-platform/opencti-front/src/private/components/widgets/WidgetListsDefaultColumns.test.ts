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

import { getWidgetColumns, getDefaultWidgetColumns } from './WidgetListsDefaultColumns';

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
});
