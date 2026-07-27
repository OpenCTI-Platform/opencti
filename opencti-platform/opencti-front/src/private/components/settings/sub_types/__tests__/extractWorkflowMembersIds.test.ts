import { describe, expect, it } from 'vitest';
import { SubTypeWorkflowQuery$data } from '../__generated__/SubTypeWorkflowQuery.graphql';
import { extractWorkflowMembersIds } from '../SubTypeWorkflow';

type WorkflowDef = SubTypeWorkflowQuery$data['workflowDefinition'];

const emptyDef = (overrides: Partial<NonNullable<WorkflowDef>> = {}): NonNullable<WorkflowDef> => ({
  id: 'wf-1',
  name: 'Test',
  published: false,
  hasPublishedVersion: false,
  errors: [],
  initialState: '',
  states: [],
  transitions: [],
  ...overrides,
});

describe('extractWorkflowMembersIds', () => {
  it('returns empty array for null workflowDefinition', () => {
    expect(extractWorkflowMembersIds(null)).toEqual([]);
  });

  it('returns empty array for undefined workflowDefinition', () => {
    expect(extractWorkflowMembersIds(undefined as never)).toEqual([]);
  });

  it('returns empty array when there are no actions', () => {
    expect(extractWorkflowMembersIds(emptyDef())).toEqual([]);
  });

  describe('updateAuthorizedMembers', () => {
    it('extracts member ids from state onEnter actions', () => {
      const def = emptyDef({
        states: [{
          statusId: 's1',
          onEnter: [{
            type: 'updateAuthorizedMembers',
            params: { authorized_members: [{ id: 'user-1', access_right: 'view' }] },
          }],
          onExit: [],
        }],
      });

      expect(extractWorkflowMembersIds(def)).toEqual(['user-1']);
    });

    it('extracts member ids from state onExit actions', () => {
      const def = emptyDef({
        states: [{
          statusId: 's1',
          onEnter: [],
          onExit: [{
            type: 'updateAuthorizedMembers',
            params: { authorized_members: [{ id: 'user-2', access_right: 'admin' }] },
          }],
        }],
      });

      expect(extractWorkflowMembersIds(def)).toEqual(['user-2']);
    });

    it('extracts groups_restriction_ids alongside member ids', () => {
      const def = emptyDef({
        states: [{
          statusId: 's1',
          onEnter: [{
            type: 'updateAuthorizedMembers',
            params: {
              authorized_members: [{
                id: 'user-1',
                access_right: 'view',
                groups_restriction_ids: ['group-1', 'group-2'],
              }],
            },
          }],
          onExit: [],
        }],
      });

      expect(extractWorkflowMembersIds(def)).toEqual(['user-1', 'group-1', 'group-2']);
    });

    it('extracts member ids from transition syncActions', () => {
      const def = emptyDef({
        transitions: [{
          from: ['s1'],
          to: 's2',
          event: 'go',
          conditions: {},
          comment: null,
          asyncActions: [],
          syncActions: [{
            type: 'updateAuthorizedMembers',
            params: { authorized_members: [{ id: 'user-3', access_right: 'edit' }] },
          }],
        }],
      });

      expect(extractWorkflowMembersIds(def)).toEqual(['user-3']);
    });
  });

  describe('asyncBulkAction', () => {
    it('extracts org ids from SHARE asyncBulkAction in transition asyncActions', () => {
      const def = emptyDef({
        transitions: [{
          from: ['s1'],
          to: 's2',
          event: 'share',
          conditions: {},
          comment: null,
          asyncActions: [{
            type: 'asyncBulkAction',
            params: {
              actions: [{ type: 'SHARE', context: { values: ['org-1', 'org-2'] } }],
            },
          }],
          syncActions: [],
        }],
      });

      expect(extractWorkflowMembersIds(def)).toEqual(['org-1', 'org-2']);
    });

    it('extracts org ids from UNSHARE asyncBulkAction', () => {
      const def = emptyDef({
        transitions: [{
          from: ['s1'],
          to: 's2',
          event: 'unshare',
          conditions: {},
          comment: null,
          asyncActions: [{
            type: 'asyncBulkAction',
            params: {
              actions: [{ type: 'UNSHARE', context: { values: ['org-3'] } }],
            },
          }],
          syncActions: [],
        }],
      });

      expect(extractWorkflowMembersIds(def)).toEqual(['org-3']);
    });
  });

  describe('deduplication', () => {
    it('deduplicates ids appearing in multiple states', () => {
      const def = emptyDef({
        states: [
          {
            statusId: 's1',
            onEnter: [{
              type: 'updateAuthorizedMembers',
              params: { authorized_members: [{ id: 'user-1', access_right: 'view' }] },
            }],
            onExit: [],
          },
          {
            statusId: 's2',
            onEnter: [{
              type: 'updateAuthorizedMembers',
              params: { authorized_members: [{ id: 'user-1', access_right: 'admin' }] },
            }],
            onExit: [],
          },
        ],
      });

      expect(extractWorkflowMembersIds(def)).toEqual(['user-1']);
    });

    it('deduplicates ids shared between members and group restrictions', () => {
      const def = emptyDef({
        states: [{
          statusId: 's1',
          onEnter: [{
            type: 'updateAuthorizedMembers',
            params: {
              authorized_members: [
                { id: 'group-1', access_right: 'view' },
                { id: 'user-1', access_right: 'admin', groups_restriction_ids: ['group-1'] },
              ],
            },
          }],
          onExit: [],
        }],
      });

      expect(extractWorkflowMembersIds(def)).toEqual(['group-1', 'user-1']);
    });

    it('collects ids from both states and transitions without duplicates', () => {
      const def = emptyDef({
        states: [{
          statusId: 's1',
          onEnter: [{
            type: 'updateAuthorizedMembers',
            params: { authorized_members: [{ id: 'user-1', access_right: 'view' }] },
          }],
          onExit: [],
        }],
        transitions: [{
          from: ['s1'],
          to: 's2',
          event: 'go',
          conditions: {},
          comment: null,
          asyncActions: [{
            type: 'asyncBulkAction',
            params: { actions: [{ type: 'SHARE', context: { values: ['user-1', 'org-1'] } }] },
          }],
          syncActions: [],
        }],
      });

      expect(extractWorkflowMembersIds(def)).toEqual(['user-1', 'org-1']);
    });
  });
});
