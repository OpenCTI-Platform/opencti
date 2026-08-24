import { describe, expect, it } from 'vitest';
import { DataTableToolBar } from '../DataTableToolBar';

describe('DataTableToolBar - Apply transition (mass real-transition frontend)', () => {
  describe('buildTransitionEventOptions', () => {
    it('dedupes transitions sharing the same event name and sorts alphabetically', () => {
      const transitions = [
        { event: 'reject' },
        { event: 'approve' },
        { event: 'approve' },
      ];
      expect(DataTableToolBar.buildTransitionEventOptions(transitions)).toEqual([
        { label: 'approve', value: 'approve' },
        { label: 'reject', value: 'reject' },
      ]);
    });

    it('returns an empty array when there are no transitions', () => {
      expect(DataTableToolBar.buildTransitionEventOptions(undefined)).toEqual([]);
      expect(DataTableToolBar.buildTransitionEventOptions([])).toEqual([]);
    });
  });

  describe('buildActionFromInput', () => {
    it('remaps the internal "x_opencti_workflow_id_transition" sentinel to the real workflow field, carrying eventName via options and never leaking the sentinel', () => {
      const action = DataTableToolBar.buildActionFromInput({
        type: 'REPLACE',
        field: 'x_opencti_workflow_id_transition',
        fieldType: 'ATTRIBUTE',
        values: [],
        options: { eventName: 'approve' },
      });
      expect(action).toEqual({
        type: 'REPLACE',
        context: {
          field: 'x_opencti_workflow_id',
          type: 'ATTRIBUTE',
          values: [],
          options: { eventName: 'approve' },
        },
      });
      expect(JSON.stringify(action)).not.toContain('x_opencti_workflow_id_transition');
    });

    it('leaves the existing legacy bypass "x_opencti_workflow_id" field untouched (no options remap)', () => {
      const action = DataTableToolBar.buildActionFromInput({
        type: 'REPLACE',
        field: 'x_opencti_workflow_id',
        fieldType: 'ATTRIBUTE',
        values: ['status-1'],
        options: undefined,
      });
      expect(action).toEqual({
        type: 'REPLACE',
        context: {
          field: 'x_opencti_workflow_id',
          type: 'ATTRIBUTE',
          values: ['status-1'],
          options: undefined,
        },
      });
    });

    it('still applies the existing category-attribute remap for unrelated fields (regression guard)', () => {
      const action = DataTableToolBar.buildActionFromInput({
        type: 'REPLACE',
        field: 'case_severity_ov',
        fieldType: 'ATTRIBUTE',
        values: [{ label: 'high' }],
        options: undefined,
      });
      expect(action).toEqual({
        type: 'REPLACE',
        context: {
          field: 'severity',
          type: 'ATTRIBUTE',
          values: ['high'],
          options: undefined,
        },
      });
    });

    it('passes through a plain field unchanged (regression guard)', () => {
      const action = DataTableToolBar.buildActionFromInput({
        type: 'ADD',
        field: 'object-label',
        fieldType: 'RELATION',
        values: ['label-1'],
        options: undefined,
      });
      expect(action).toEqual({
        type: 'ADD',
        context: {
          field: 'object-label',
          type: 'RELATION',
          values: ['label-1'],
          options: undefined,
        },
      });
    });
  });
});
