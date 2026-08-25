import { beforeEach, describe, expect, it, vi } from 'vitest';
import workflowResolvers from '../../../src/modules/workflow/api/workflow-resolvers';
import { reportWorkflowAsyncActionResult } from '../../../src/modules/workflow/domain/workflow-async-completion';
import * as workflowDomain from '../../../src/modules/workflow/domain/workflow-domain';
import {
    clearWorkflowPendingState,
    getAllowedTransitions,
    getWorkflowPublishedVersionId,
    setWorkflowStatus,
    triggerWorkflowEvent,
} from '../../../src/modules/workflow/domain/workflow-domain';
import type { AuthContext } from '../../../src/types/user';

// Mock all workflow domain functions
vi.mock('../../../src/modules/workflow/domain/workflow-domain', () => ({
  getWorkflowDefinition: vi.fn(),
  hasPublishedWorkflowDefinition: vi.fn(),
  getWorkflowMigrationPreview: vi.fn(),
  getWorkflowInstance: vi.fn(),
  getAllowedTransitions: vi.fn(),
  setWorkflowDefinition: vi.fn(),
  publishWorkflowDefinition: vi.fn(),
  deleteWorkflowDefinition: vi.fn(),
  restorePublishedWorkflowDefinition: vi.fn(),
  triggerWorkflowEvent: vi.fn(),
  setWorkflowStatus: vi.fn(),
  clearWorkflowPendingState: vi.fn(),
  getWorkflowPublishedVersionId: vi.fn(),
}));

vi.mock('../../../src/modules/workflow/domain/workflow-async-completion', () => ({
  reportWorkflowAsyncActionResult: vi.fn(),
}));

const mockContext = { user: { id: 'user-id' } } as any;

beforeEach(() => {
  vi.clearAllMocks();
});

// ---------------------------------------------------------------------------
// WorkflowTransition field resolver
// ---------------------------------------------------------------------------

describe('WorkflowTransition resolver – isClosingTransition field', () => {
  it('should return true when isClosingTransition is true on the transition', () => {
    const transition = { event: 'close', toState: 'closed', isClosingTransition: true, actions: [] };
    expect(workflowResolvers.WorkflowTransition.isClosingTransition(transition)).toBe(true);
  });

  it('should return false when isClosingTransition is undefined on the transition', () => {
    const transition = { event: 'review', toState: 'reviewed', actions: [] };
    expect(workflowResolvers.WorkflowTransition.isClosingTransition(transition)).toBe(false);
  });
});

describe('WorkflowTransition resolver – comment field', () => {
  it('should return the comment when it is defined on the transition', () => {
    const transition = { event: 'review', toState: 'reviewed', comment: 'Requires approval', actions: [] };
    const result = workflowResolvers.WorkflowTransition.comment(transition);
    expect(result).toBe('Requires approval');
  });

  it('should return null when comment is undefined on the transition', () => {
    const transition = { event: 'review', toState: 'reviewed', actions: [] };
    const result = workflowResolvers.WorkflowTransition.comment(transition);
    expect(result).toBeNull();
  });

  it('should return null when comment is explicitly null on the transition', () => {
    const transition = { event: 'review', toState: 'reviewed', comment: null, actions: [] };
    const result = workflowResolvers.WorkflowTransition.comment(transition);
    expect(result).toBeNull();
  });

  it('should return an empty string when comment is an empty string', () => {
    const transition = { event: 'review', toState: 'reviewed', comment: '', actions: [] };
    const result = workflowResolvers.WorkflowTransition.comment(transition);
    // empty string is falsy – ?? keeps it as empty string (not null)
    expect(result).toBe('');
  });
});

// ---------------------------------------------------------------------------
// WorkflowInstance.lastHistoryEntry – comment in history
// ---------------------------------------------------------------------------

describe('WorkflowInstance resolver – lastHistoryEntry comment', () => {
  it('should return the most recent history entry, including its comment', () => {
    const instance = {
      id: 'inst-1',
      currentState: 'reviewed',
      allowedTransitions: [],
      history: [
        { state: 'draft', event: 'init', user_id: 'u1', timestamp: '2024-01-01T00:00:00Z' },
        { state: 'reviewed', event: 'review', user_id: 'u1', timestamp: '2024-01-02T00:00:00Z', comment: 'Looks good' },
      ],
    };

    const entry = workflowResolvers.WorkflowInstance.lastHistoryEntry(instance);
    expect(entry).not.toBeNull();
    expect(entry!.comment).toBe('Looks good');
    expect(entry!.event).toBe('review');
  });

  it('should return null when lastHistoryEntry has no comment', () => {
    const instance = {
      id: 'inst-1',
      currentState: 'draft',
      allowedTransitions: [],
      history: [
        { state: 'draft', event: 'init', user_id: 'u1', timestamp: '2024-01-01T00:00:00Z' },
      ],
    };

    const entry = workflowResolvers.WorkflowInstance.lastHistoryEntry(instance);
    expect(entry).not.toBeNull();
    expect(entry!.comment).toBeUndefined();
  });

  it('should return null when history is empty', () => {
    const instance = { id: 'inst-1', currentState: 'draft', allowedTransitions: [], history: [] };
    const entry = workflowResolvers.WorkflowInstance.lastHistoryEntry(instance);
    expect(entry).toBeNull();
  });

  it('should return null when history is undefined', () => {
    const instance = { id: 'inst-1', currentState: 'draft', allowedTransitions: [] };
    const entry = workflowResolvers.WorkflowInstance.lastHistoryEntry(instance);
    expect(entry).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Mutation.triggerWorkflowEvent – comment forwarding
// ---------------------------------------------------------------------------

describe('Mutation.triggerWorkflowEvent resolver – comment forwarding', () => {
  it('should forward the comment to the domain function when provided', async () => {
    (triggerWorkflowEvent as any).mockResolvedValue({ success: true, newState: 'reviewed', instance: {}, entity: {} });

    await workflowResolvers.Mutation.triggerWorkflowEvent(
      {},
      { entityId: 'entity-id', eventName: 'review', comment: 'Approved for review' },
      mockContext,
    );

    expect(triggerWorkflowEvent).toHaveBeenCalledWith(
      mockContext,
      mockContext.user,
      'entity-id',
      'review',
      'Approved for review',
      {},
      undefined,
    );
  });

  it('should forward undefined comment to the domain function when no comment is provided', async () => {
    (triggerWorkflowEvent as any).mockResolvedValue({ success: true, newState: 'reviewed', instance: {}, entity: {} });

    await workflowResolvers.Mutation.triggerWorkflowEvent(
      {},
      { entityId: 'entity-id', eventName: 'review' },
      mockContext,
    );

    expect(triggerWorkflowEvent).toHaveBeenCalledWith(
      mockContext,
      mockContext.user,
      'entity-id',
      'review',
      undefined,
      {},
      undefined,
    );
  });

  it('should forward the closingReason to the domain function when provided', async () => {
    (triggerWorkflowEvent as any).mockResolvedValue({ success: true, newState: 'reviewed', instance: {}, entity: {} });

    await workflowResolvers.Mutation.triggerWorkflowEvent(
      {},
      { entityId: 'entity-id', eventName: 'review', closingReason: 'No longer relevant' },
      mockContext,
    );

    expect(triggerWorkflowEvent).toHaveBeenCalledWith(
      mockContext,
      mockContext.user,
      'entity-id',
      'review',
      undefined,
      {},
      'No longer relevant',
    );
  });

  it('should throw GraphQLError when closingReason exceeds 1000 characters', () => {
    const longReason = 'a'.repeat(1001);

    expect(() =>
      workflowResolvers.Mutation.triggerWorkflowEvent(
        {},
        { entityId: 'entity-id', eventName: 'review', closingReason: longReason },
        mockContext,
      ),
    ).toThrow('Closing reason exceeds maximum allowed length of 1000 characters.');
  });
});

// ---------------------------------------------------------------------------
// Mutation.setWorkflowStatus (Task 9) – bypass-update resolver
// ---------------------------------------------------------------------------

describe('Mutation.setWorkflowStatus resolver', () => {
  it('should forward entityId, targetStatusId, applyTransitionActions and the trimmed comment', async () => {
    (setWorkflowStatus as any).mockResolvedValue({ success: true, newState: 'reviewing', instance: {}, entity: {} });

    await workflowResolvers.Mutation.setWorkflowStatus(
      {},
      { entityId: 'entity-id', targetStatusId: 'status-id', applyTransitionActions: true, comment: '  skip ahead  ' },
      mockContext,
    );

    expect(setWorkflowStatus).toHaveBeenCalledWith(
      mockContext, mockContext.user, 'entity-id', 'status-id', true, 'skip ahead', undefined,
    );
  });

  it('should forward undefined comment when none is provided', async () => {
    (setWorkflowStatus as any).mockResolvedValue({ success: true, newState: 'reviewing', instance: {}, entity: {} });

    await workflowResolvers.Mutation.setWorkflowStatus(
      {},
      { entityId: 'entity-id', targetStatusId: 'status-id', applyTransitionActions: false },
      mockContext,
    );

    expect(setWorkflowStatus).toHaveBeenCalledWith(
      mockContext, mockContext.user, 'entity-id', 'status-id', false, undefined, undefined,
    );
  });

  it('should throw GraphQLError when comment exceeds 1000 characters', () => {
    const longComment = 'a'.repeat(1001);

    expect(() =>
      workflowResolvers.Mutation.setWorkflowStatus(
        {},
        { entityId: 'entity-id', targetStatusId: 'status-id', applyTransitionActions: false, comment: longComment },
        mockContext,
      ),
    ).toThrow('Comment exceeds maximum allowed length of 1000 characters.');
  });

  it('should forward the closingReason to the domain function when provided', async () => {
    (setWorkflowStatus as any).mockResolvedValue({ success: true, newState: 'reviewing', instance: {}, entity: {} });

    await workflowResolvers.Mutation.setWorkflowStatus(
      {},
      { entityId: 'entity-id', targetStatusId: 'status-id', applyTransitionActions: false, closingReason: '  skip ahead reason  ' },
      mockContext,
    );

    expect(setWorkflowStatus).toHaveBeenCalledWith(
      mockContext, mockContext.user, 'entity-id', 'status-id', false, undefined, 'skip ahead reason',
    );
  });

  it('should throw GraphQLError when closingReason exceeds 1000 characters', () => {
    const longReason = 'a'.repeat(1001);

    expect(() =>
      workflowResolvers.Mutation.setWorkflowStatus(
        {},
        { entityId: 'entity-id', targetStatusId: 'status-id', applyTransitionActions: false, closingReason: longReason },
        mockContext,
      ),
    ).toThrow('Closing reason exceeds maximum allowed length of 1000 characters.');
  });
});

// ---------------------------------------------------------------------------
// Query.allowedTransitions – comment exposed through resolver
// ---------------------------------------------------------------------------

describe('Query.allowedTransitions resolver – comment field', () => {
  it('should return transitions that include the comment field', async () => {
    (getAllowedTransitions as any).mockResolvedValue([
      { event: 'review', toState: 'reviewed', comment: 'Requires manager sign-off', actions: [] },
      { event: 'reject', toState: 'rejected', actions: [] },
    ]);

    const result = await workflowResolvers.Query.allowedTransitions({}, { entityId: 'entity-id' }, mockContext);

    expect(result).toHaveLength(2);
    expect(result[0].comment).toBe('Requires manager sign-off');
    expect(result[1].comment).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// WorkflowTriggerResult resolver – status from newState
// ---------------------------------------------------------------------------

describe('WorkflowTriggerResult resolver – status field', () => {
  it('should return a status object derived from newState when present', () => {
    const triggerResult = { newState: 'reviewed', instance: { currentStateOrder: 4 }, entity: {} };
    const status = workflowResolvers.WorkflowTriggerResult.status(triggerResult);
    expect(status).toEqual({ id: 'wf-status--reviewed', template_id: 'reviewed', order: 4 });
  });

  it('should return null when newState is absent', () => {
    const triggerResult = { instance: {}, entity: {} };
    const status = workflowResolvers.WorkflowTriggerResult.status(triggerResult);
    expect(status).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Mutation.triggerWorkflowEvent – comment validation and normalization
// ---------------------------------------------------------------------------

describe('Mutation.triggerWorkflowEvent resolver – comment validation', () => {
  it('should throw GraphQLError when comment exceeds 1000 characters', () => {
    const longComment = 'a'.repeat(1001);

    expect(() =>
      workflowResolvers.Mutation.triggerWorkflowEvent(
        {},
        { entityId: 'entity-id', eventName: 'review', comment: longComment },
        mockContext,
      ),
    ).toThrow('Comment exceeds maximum allowed length of 1000 characters.');
  });

  it('should NOT throw when comment is exactly 1000 characters', async () => {
    (triggerWorkflowEvent as any).mockResolvedValue({ success: true, newState: 'reviewed', instance: {}, entity: {} });
    const exactComment = 'a'.repeat(1000);

    await expect(
      workflowResolvers.Mutation.triggerWorkflowEvent(
        {},
        { entityId: 'entity-id', eventName: 'review', comment: exactComment },
        mockContext,
      ),
    ).resolves.not.toThrow();

    expect(triggerWorkflowEvent).toHaveBeenCalledWith(
      mockContext, mockContext.user, 'entity-id', 'review', exactComment, {}, undefined,
    );
  });

  it('should trim the comment before passing it to the domain', async () => {
    (triggerWorkflowEvent as any).mockResolvedValue({ success: true, newState: 'reviewed', instance: {}, entity: {} });

    await workflowResolvers.Mutation.triggerWorkflowEvent(
      {},
      { entityId: 'entity-id', eventName: 'review', comment: '  trimmed comment  ' },
      mockContext,
    );

    expect(triggerWorkflowEvent).toHaveBeenCalledWith(
      mockContext, mockContext.user, 'entity-id', 'review', 'trimmed comment', {}, undefined,
    );
  });

  it('should convert null comment to undefined before passing to the domain', async () => {
    (triggerWorkflowEvent as any).mockResolvedValue({ success: true, newState: 'reviewed', instance: {}, entity: {} });

    await workflowResolvers.Mutation.triggerWorkflowEvent(
      {},
      { entityId: 'entity-id', eventName: 'review', comment: null },
      mockContext,
    );

    expect(triggerWorkflowEvent).toHaveBeenCalledWith(
      mockContext, mockContext.user, 'entity-id', 'review', undefined, {}, undefined,
    );
  });
});

describe('workflow-resolvers', () => {
  const mockContext: AuthContext = {
    user: { id: 'user-123', name: 'Test User' },
  } as AuthContext;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Query resolvers', () => {
    describe('workflowDefinition', () => {
      it('should call getWorkflowDefinition with default allowDraft=false', async () => {
        const mockDefinition = {
          id: 'def-1',
          name: 'Test Workflow',
          published: true,
          initialState: 'open',
          states: [],
          transitions: [],
        };
        vi.mocked(workflowDomain.getWorkflowDefinition).mockResolvedValue(mockDefinition);

        const result = await workflowResolvers.Query.workflowDefinition(
          {},
          { entityType: 'Case' },
          mockContext,
        );

        expect(workflowDomain.getWorkflowDefinition).toHaveBeenCalledWith(
          mockContext,
          mockContext.user,
          'Case',
          false,
          undefined,
        );
        expect(result).toBe(mockDefinition);
      });

      it('should call getWorkflowDefinition with allowDraft=true when specified', async () => {
        const mockDefinition = {
          id: 'def-2',
          name: 'Draft Workflow',
          published: false,
          initialState: 'draft',
          states: [],
          transitions: [],
        };
        vi.mocked(workflowDomain.getWorkflowDefinition).mockResolvedValue(mockDefinition);

        const result = await workflowResolvers.Query.workflowDefinition(
          {},
          { entityType: 'Incident', allowDraft: true },
          mockContext,
        );

        expect(workflowDomain.getWorkflowDefinition).toHaveBeenCalledWith(
          mockContext,
          mockContext.user,
          'Incident',
          true,
          undefined,
        );
        expect(result).toBe(mockDefinition);
      });
    });

    describe('workflowDefinitionPublished', () => {
      it('should call hasPublishedWorkflowDefinition with correct arguments and return its result', async () => {
        vi.mocked(workflowDomain.hasPublishedWorkflowDefinition).mockResolvedValue(true);

        const result = await workflowResolvers.Query.workflowDefinitionPublished(
          {},
          { entityType: 'StixSightingRelationship' },
          mockContext,
        );

        expect(workflowDomain.hasPublishedWorkflowDefinition).toHaveBeenCalledWith(
          mockContext,
          mockContext.user,
          'StixSightingRelationship',
        );
        expect(result).toBe(true);
      });

      it('should return false when no published definition exists', async () => {
        vi.mocked(workflowDomain.hasPublishedWorkflowDefinition).mockResolvedValue(false);

        const result = await workflowResolvers.Query.workflowDefinitionPublished(
          {},
          { entityType: 'Incident' },
          mockContext,
        );

        expect(result).toBe(false);
      });
    });

    describe('workflowMigrationPreview', () => {
      it('should shape byScope into a results array per scope', async () => {
        vi.mocked(workflowDomain.getWorkflowMigrationPreview).mockResolvedValue({
          byScope: {
            GLOBAL: {
              definition: { initialState: 't1', states: [{ statusId: 't1' }], transitions: [] },
              diagnostics: [],
            },
          },
        } as any);

        const result = await workflowResolvers.Query.workflowMigrationPreview(
          {},
          { entityType: 'Incident' },
          mockContext,
        );

        expect(workflowDomain.getWorkflowMigrationPreview).toHaveBeenCalledWith(
          mockContext,
          mockContext.user,
          'Incident',
        );
        expect(result).toEqual({
          entityType: 'Incident',
          results: [
            {
              scope: 'GLOBAL',
              initialState: 't1',
              states: [{ statusId: 't1' }],
              transitions: [],
              diagnostics: [],
            },
          ],
        });
      });

      it('should return an empty results array when no scope has any Status data', async () => {
        vi.mocked(workflowDomain.getWorkflowMigrationPreview).mockResolvedValue({ byScope: {} } as any);

        const result = await workflowResolvers.Query.workflowMigrationPreview(
          {},
          { entityType: 'Incident' },
          mockContext,
        );

        expect(result).toEqual({ entityType: 'Incident', results: [] });
      });
    });

    describe('workflowInstance', () => {
      it('should call getWorkflowInstance with correct arguments', async () => {
        const mockInstance = { id: 'inst-1', currentState: 'open' };
        vi.mocked(workflowDomain.getWorkflowInstance).mockResolvedValue(mockInstance);

        const result = await workflowResolvers.Query.workflowInstance(
          {},
          { entityId: 'entity-123' },
          mockContext,
        );

        expect(workflowDomain.getWorkflowInstance).toHaveBeenCalledWith(
          mockContext,
          mockContext.user,
          'entity-123',
        );
        expect(result).toBe(mockInstance);
      });
    });

    describe('allowedTransitions', () => {
      it('should call getAllowedTransitions with correct arguments', async () => {
        const mockTransitions = [{ event: 'close', toState: 'closed', actions: [], requiresShareOrganizationInput: false, requiresUnshareOrganizationInput: false }];
        vi.mocked(workflowDomain.getAllowedTransitions).mockResolvedValue(mockTransitions);

        const result = await workflowResolvers.Query.allowedTransitions(
          {},
          { entityId: 'entity-789' },
          mockContext,
        );

        expect(workflowDomain.getAllowedTransitions).toHaveBeenCalledWith(
          mockContext,
          mockContext.user,
          'entity-789',
        );
        expect(result).toBe(mockTransitions);
      });
    });
  });

  describe('Mutation resolvers', () => {
    describe('workflowDefinitionSet', () => {
      it('should call setWorkflowDefinition with correct arguments', async () => {
        const mockDefinition = {
          id: 'def-3',
          errors: [],
          published: false,
          workflow_id: 'workflow-1',
          target_type: 'Report',
        };
        const definitionJson = JSON.stringify({ statuses: [], transitions: [] });
        vi.mocked(workflowDomain.setWorkflowDefinition).mockResolvedValue(mockDefinition);

        const result = await workflowResolvers.Mutation.workflowDefinitionSet(
          {},
          { entityType: 'Report', definition: definitionJson },
          mockContext,
        );

        expect(workflowDomain.setWorkflowDefinition).toHaveBeenCalledWith(
          mockContext,
          mockContext.user,
          'Report',
          definitionJson,
          undefined,
        );
        expect(result).toBe(mockDefinition);
      });
    });

    describe('workflowDefinitionPublish', () => {
      it('should call publishWorkflowDefinition with correct arguments', async () => {
        const mockPublished = {
          id: 'def-4',
          errors: [],
          published: true,
          workflow_id: 'workflow-2',
          target_type: 'Task',
        };
        vi.mocked(workflowDomain.publishWorkflowDefinition).mockResolvedValue(mockPublished);

        const result = await workflowResolvers.Mutation.workflowDefinitionPublish(
          {},
          { entityType: 'Task' },
          mockContext,
        );

        expect(workflowDomain.publishWorkflowDefinition).toHaveBeenCalledWith(
          mockContext,
          mockContext.user,
          'Task',
          undefined,
        );
        expect(result).toBe(mockPublished);
      });
    });

    describe('workflowDefinitionDelete', () => {
      it('should call deleteWorkflowDefinition with correct arguments', async () => {
        const mockDeleted = {
          id: 'def-5',
          entity_type: 'EntitySetting',
        } as any;
        vi.mocked(workflowDomain.deleteWorkflowDefinition).mockResolvedValue(mockDeleted);

        const result = await workflowResolvers.Mutation.workflowDefinitionDelete(
          {},
          { entityType: 'Case' },
          mockContext,
        );

        expect(workflowDomain.deleteWorkflowDefinition).toHaveBeenCalledWith(
          mockContext,
          mockContext.user,
          'Case',
          undefined,
        );
        expect(result).toBe(mockDeleted);
      });
    });

    describe('workflowDefinitionRestorePublished', () => {
      it('should call restorePublishedWorkflowDefinition with correct arguments', async () => {
        const mockRestored = {
          id: 'def-6',
          workflow_id: 'workflow-3',
          target_type: 'Incident',
          errors: [],
          published: true,
        } as any;
        vi.mocked(workflowDomain.restorePublishedWorkflowDefinition).mockResolvedValue(mockRestored);

        const result = await workflowResolvers.Mutation.workflowDefinitionRestorePublished(
          {},
          { entityType: 'Incident' },
          mockContext,
        );

        expect(workflowDomain.restorePublishedWorkflowDefinition).toHaveBeenCalledWith(
          mockContext,
          mockContext.user,
          'Incident',
          undefined,
        );
        expect(result).toBe(mockRestored);
      });
    });

    describe('triggerWorkflowEvent', () => {
      it('should call triggerWorkflowEvent with correct arguments', async () => {
        const mockResult = { success: true, newState: 'closed', instance: {}, entity: {} };
        vi.mocked(workflowDomain.triggerWorkflowEvent).mockResolvedValue(mockResult);

        const result = await workflowResolvers.Mutation.triggerWorkflowEvent(
          {},
          { entityId: 'entity-999', eventName: 'close' },
          mockContext,
        );

        expect(workflowDomain.triggerWorkflowEvent).toHaveBeenCalledWith(
          mockContext,
          mockContext.user,
          'entity-999',
          'close',
          undefined,
          {},
          undefined,
        );
        expect(result).toBe(mockResult);
      });
    });
  });

  describe('WorkflowInstance type resolvers', () => {
    describe('id', () => {
      it('should return id when present', () => {
        const instance = { id: 'inst-123', internal_id: 'internal-456' };
        const result = workflowResolvers.WorkflowInstance.id(instance);
        expect(result).toBe('inst-123');
      });

      it('should return internal_id when id is not present', () => {
        const instance = { internal_id: 'internal-789' };
        const result = workflowResolvers.WorkflowInstance.id(instance);
        expect(result).toBe('internal-789');
      });
    });

    describe('currentState', () => {
      it('should return currentState', () => {
        const instance = { currentState: 'in-progress' };
        const result = workflowResolvers.WorkflowInstance.currentState(instance);
        expect(result).toBe('in-progress');
      });
    });

    describe('currentStatus', () => {
      it('should return status object with namespaced id, template_id and order', () => {
        const instance = { currentState: 'open', currentStateOrder: 2 };
        const result = workflowResolvers.WorkflowInstance.currentStatus(instance);
        expect(result).toEqual({ id: 'wf-status--open', template_id: 'open', order: 2 });
      });
    });

    describe('allowedTransitions', () => {
      it('should return allowedTransitions', () => {
        const transitions = [{ toState: 'closed' }];
        const instance = { allowedTransitions: transitions };
        const result = workflowResolvers.WorkflowInstance.allowedTransitions(instance);
        expect(result).toBe(transitions);
      });
    });
  });

  describe('WorkflowTransition type resolvers', () => {
    describe('toStatus', () => {
      it('should return status object from toState', () => {
        const transition = { toState: 'closed', toStateOrder: 3 };
        const result = workflowResolvers.WorkflowTransition.toStatus(transition);
        expect(result).toEqual({ id: 'wf-status--closed', template_id: 'closed', order: 3 });
      });
    });

    describe('actions', () => {
      it('should return actions when present', () => {
        const actions = [{ type: 'notify' }];
        const transition = { actions };
        const result = workflowResolvers.WorkflowTransition.actions(transition);
        expect(result).toBe(actions);
      });

      it('should return empty array when actions is null', () => {
        const transition = { actions: null };
        const result = workflowResolvers.WorkflowTransition.actions(transition);
        expect(result).toEqual([]);
      });

      it('should return empty array when actions is undefined', () => {
        const transition = {};
        const result = workflowResolvers.WorkflowTransition.actions(transition);
        expect(result).toEqual([]);
      });
    });
  });

  describe('WorkflowTriggerResult type resolvers', () => {
    describe('status', () => {
      it('should return status object when newState is present', () => {
        const result = { newState: 'completed', instance: { currentStateOrder: 1 } };
        const status = workflowResolvers.WorkflowTriggerResult.status(result);
        expect(status).toEqual({ id: 'wf-status--completed', template_id: 'completed', order: 1 });
      });

      it('should return null when newState is not present', () => {
        const result = {};
        const status = workflowResolvers.WorkflowTriggerResult.status(result);
        expect(status).toBeNull();
      });

      it('should return null when newState is null', () => {
        const result = { newState: null };
        const status = workflowResolvers.WorkflowTriggerResult.status(result);
        expect(status).toBeNull();
      });
    });

    describe('instance', () => {
      it('should return instance from result', () => {
        const instance = { id: 'inst-1' };
        const result = { instance };
        const returned = workflowResolvers.WorkflowTriggerResult.instance(result);
        expect(returned).toBe(instance);
      });
    });

    describe('entity', () => {
      it('should return entity from result', () => {
        const entity = { id: 'entity-1' };
        const result = { entity };
        const returned = workflowResolvers.WorkflowTriggerResult.entity(result);
        expect(returned).toBe(entity);
      });
    });
  });

  describe('DraftWorkspace type resolvers', () => {
    describe('workflowInstance', () => {
      it('should load through context.batch.workflowInstancesBatchLoader with the draft entity', async () => {
        const mockInstance = { id: 'inst-2', currentState: 'draft' };
        const load = vi.fn().mockResolvedValue(mockInstance);
        const batchContext = { ...mockContext, batch: { workflowInstancesBatchLoader: { load } } };

        const draft = { id: 'draft-123' };
        const result = await workflowResolvers.DraftWorkspace.workflowInstance(
          draft,
          {},
          batchContext as any,
        );

        expect(load).toHaveBeenCalledWith(draft);
        expect(result).toBe(mockInstance);
      });

      it('should pass through the entity object as-is (no id extraction needed for the batch loader)', async () => {
        const load = vi.fn().mockResolvedValue(null);
        const batchContext = { ...mockContext, batch: { workflowInstancesBatchLoader: { load } } };

        const draft = { internal_id: 'internal-draft-456' };
        await workflowResolvers.DraftWorkspace.workflowInstance(
          draft,
          {},
          batchContext as any,
        );

        expect(load).toHaveBeenCalledWith(draft);
      });
    });
  });

  describe('StixSightingRelationship type resolvers', () => {
    describe('workflowInstance', () => {
      it('should load through context.batch.workflowInstancesBatchLoader with the relationship entity', async () => {
        const mockInstance = { id: 'inst-5', currentState: 'open' };
        const load = vi.fn().mockResolvedValue(mockInstance);
        const batchContext = { ...mockContext, batch: { workflowInstancesBatchLoader: { load } } };

        const relationship = { id: 'sighting-1', entity_type: 'stix-sighting-relationship' };
        const result = await workflowResolvers.StixSightingRelationship.workflowInstance(
          relationship,
          {},
          batchContext as any,
        );

        expect(load).toHaveBeenCalledWith(relationship);
        expect(result).toBe(mockInstance);
      });
    });
  });

  describe('Task 9: generic StixDomainObject type resolvers', () => {
    describe('workflowInstance', () => {
      it.each(['Report', 'Malware', 'Incident', 'Indicator', 'CaseIncident'])('%s loads through context.batch.workflowInstancesBatchLoader with the entity', async (typeName) => {
        const mockInstance = { id: 'inst-9', currentState: 'new' };
        const load = vi.fn().mockResolvedValue(mockInstance);
        const batchContext = { ...mockContext, batch: { workflowInstancesBatchLoader: { load } } };

        const entity = { id: 'entity-1' };
        const result = await (workflowResolvers as any)[typeName].workflowInstance(entity, {}, batchContext as any);

        expect(load).toHaveBeenCalledWith(entity);
        expect(result).toBe(mockInstance);
      });
    });
  });

  describe('WorkflowDefinitionMutationResult type resolvers', () => {
    describe('errors', () => {
      it('should return errors when present', () => {
        const errors = [{ message: 'Invalid transition' }];
        const result = workflowResolvers.WorkflowDefinitionMutationResult.errors({ errors });
        expect(result).toBe(errors);
      });

      it('should return empty array when errors is not present', () => {
        const result = workflowResolvers.WorkflowDefinitionMutationResult.errors({});
        expect(result).toEqual([]);
      });

      it('should return empty array when errors is null', () => {
        const result = workflowResolvers.WorkflowDefinitionMutationResult.errors({ errors: null });
        expect(result).toEqual([]);
      });
    });
  });
});

// ---------------------------------------------------------------------------
// Mutation.clearWorkflowPendingState
// ---------------------------------------------------------------------------

describe('Mutation.clearWorkflowPendingState resolver', () => {
  it('delegates to the domain function with the correct args', async () => {
    (clearWorkflowPendingState as any).mockResolvedValue({ id: 'inst-id', pendingStatus: null });

    const result = await workflowResolvers.Mutation.clearWorkflowPendingState(
      {},
      { entityId: 'entity-id' },
      mockContext,
    );

    expect(clearWorkflowPendingState).toHaveBeenCalledWith(mockContext, mockContext.user, 'entity-id');
    expect(result).toEqual({ id: 'inst-id', pendingStatus: null });
  });
});

// ---------------------------------------------------------------------------
// Mutation.reportWorkflowAsyncActionResult
// ---------------------------------------------------------------------------

describe('Mutation.reportWorkflowAsyncActionResult resolver', () => {
  it('calls reportWorkflowAsyncActionResult and returns true', async () => {
    (reportWorkflowAsyncActionResult as any).mockResolvedValue(undefined);

    const result = await workflowResolvers.Mutation.reportWorkflowAsyncActionResult(
      {},
      { workflowInstanceId: 'inst-id', workflowActionId: 'slot-id', status: 'success' },
      mockContext,
    );

    expect(reportWorkflowAsyncActionResult).toHaveBeenCalledWith(
      mockContext, mockContext.user, 'inst-id', 'slot-id', 'success', undefined,
    );
    expect(result).toBe(true);
  });

  it('forwards the error message when provided', async () => {
    (reportWorkflowAsyncActionResult as any).mockResolvedValue(undefined);

    await workflowResolvers.Mutation.reportWorkflowAsyncActionResult(
      {},
      { workflowInstanceId: 'inst-id', workflowActionId: 'slot-id', status: 'failed', error: 'task blew up' },
      mockContext,
    );

    expect(reportWorkflowAsyncActionResult).toHaveBeenCalledWith(
      mockContext, mockContext.user, 'inst-id', 'slot-id', 'failed', 'task blew up',
    );
  });
});

// ---------------------------------------------------------------------------
// WorkflowInstance – new pending fields
// ---------------------------------------------------------------------------

describe('WorkflowInstance resolver – pending fields', () => {
  it('returns pendingStatus from the instance', () => {
    expect(workflowResolvers.WorkflowInstance.pendingStatus({ pendingStatus: 'pending' })).toBe('pending');
    expect(workflowResolvers.WorkflowInstance.pendingStatus({ pendingStatus: null })).toBeNull();
    expect(workflowResolvers.WorkflowInstance.pendingStatus({})).toBeNull();
  });

  it('returns pendingError from the instance', () => {
    expect(workflowResolvers.WorkflowInstance.pendingError({ pendingError: 'some error' })).toBe('some error');
    expect(workflowResolvers.WorkflowInstance.pendingError({ pendingError: null })).toBeNull();
    expect(workflowResolvers.WorkflowInstance.pendingError({})).toBeNull();
  });

  it('returns pendingTransition from the instance', () => {
    const pt = { event: 'submit', toState: 'reviewing', triggeredAt: '2024-01-01T00:00:00Z', asyncActions: [] };
    expect(workflowResolvers.WorkflowInstance.pendingTransition({ pendingTransition: pt })).toEqual(pt);
    expect(workflowResolvers.WorkflowInstance.pendingTransition({ pendingTransition: null })).toBeNull();
    expect(workflowResolvers.WorkflowInstance.pendingTransition({})).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// WorkflowTransition – requiresOrganizationInput fields
// ---------------------------------------------------------------------------

describe('WorkflowTransition resolver – org input flags', () => {
  it('returns requiresShareOrganizationInput value or false', () => {
    expect(workflowResolvers.WorkflowTransition.requiresShareOrganizationInput({ requiresShareOrganizationInput: true })).toBe(true);
    expect(workflowResolvers.WorkflowTransition.requiresShareOrganizationInput({ requiresShareOrganizationInput: false })).toBe(false);
    expect(workflowResolvers.WorkflowTransition.requiresShareOrganizationInput({})).toBe(false);
  });

  it('returns requiresUnshareOrganizationInput value or false', () => {
    expect(workflowResolvers.WorkflowTransition.requiresUnshareOrganizationInput({ requiresUnshareOrganizationInput: true })).toBe(true);
    expect(workflowResolvers.WorkflowTransition.requiresUnshareOrganizationInput({})).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// WorkflowPendingAsyncAction – field resolvers
// ---------------------------------------------------------------------------

describe('WorkflowPendingAsyncAction resolver – field resolvers', () => {
  const slot = {
    id: 'slot-1',
    workId: 'work-1',
    type: 'asyncBulkAction',
    status: 'pending',
    processedCount: 10,
    expectedCount: 50,
    startedAt: '2024-01-01T00:00:00Z',
    lastActivityAt: '2024-01-01T01:00:00Z',
    errors: [{ message: 'err' }],
  };

  it('returns all fields from the slot', () => {
    expect(workflowResolvers.WorkflowPendingAsyncAction.id(slot)).toBe('slot-1');
    expect(workflowResolvers.WorkflowPendingAsyncAction.workId(slot)).toBe('work-1');
    expect(workflowResolvers.WorkflowPendingAsyncAction.type(slot)).toBe('asyncBulkAction');
    expect(workflowResolvers.WorkflowPendingAsyncAction.status(slot)).toBe('pending');
    expect(workflowResolvers.WorkflowPendingAsyncAction.processedCount(slot)).toBe(10);
    expect(workflowResolvers.WorkflowPendingAsyncAction.expectedCount(slot)).toBe(50);
    expect(workflowResolvers.WorkflowPendingAsyncAction.startedAt(slot)).toBe('2024-01-01T00:00:00Z');
    expect(workflowResolvers.WorkflowPendingAsyncAction.lastActivityAt(slot)).toBe('2024-01-01T01:00:00Z');
    expect(workflowResolvers.WorkflowPendingAsyncAction.errors(slot)).toEqual([{ message: 'err' }]);
  });

  it('returns null for optional numeric fields when absent', () => {
    expect(workflowResolvers.WorkflowPendingAsyncAction.processedCount({})).toBeNull();
    expect(workflowResolvers.WorkflowPendingAsyncAction.expectedCount({})).toBeNull();
    expect(workflowResolvers.WorkflowPendingAsyncAction.startedAt({})).toBeNull();
    expect(workflowResolvers.WorkflowPendingAsyncAction.lastActivityAt({})).toBeNull();
    expect(workflowResolvers.WorkflowPendingAsyncAction.errors({})).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// WorkflowPendingTransition – field resolvers
// ---------------------------------------------------------------------------

describe('WorkflowPendingTransition resolver – field resolvers', () => {
  const pt = {
    event: 'submit',
    toState: 'reviewing',
    triggeredAt: '2024-01-01T00:00:00Z',
    asyncActions: [{ id: 'slot-1' }],
  };

  it('returns all fields', () => {
    expect(workflowResolvers.WorkflowPendingTransition.event(pt)).toBe('submit');
    expect(workflowResolvers.WorkflowPendingTransition.toState(pt)).toBe('reviewing');
    expect(workflowResolvers.WorkflowPendingTransition.triggeredAt(pt)).toBe('2024-01-01T00:00:00Z');
    expect(workflowResolvers.WorkflowPendingTransition.asyncActions(pt)).toEqual([{ id: 'slot-1' }]);
  });

  it('returns empty array for asyncActions when absent', () => {
    expect(workflowResolvers.WorkflowPendingTransition.asyncActions({})).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// WorkflowTriggerResult – executionStatus and pendingTransition
// ---------------------------------------------------------------------------

describe('WorkflowTriggerResult resolver – executionStatus and pendingTransition', () => {
  it('returns executionStatus when present', () => {
    expect(workflowResolvers.WorkflowTriggerResult.executionStatus({ executionStatus: 'pending' })).toBe('pending');
    expect(workflowResolvers.WorkflowTriggerResult.executionStatus({ executionStatus: 'completed' })).toBe('completed');
    expect(workflowResolvers.WorkflowTriggerResult.executionStatus({})).toBeNull();
  });

  it('returns instance.pendingTransition for pendingTransition field', () => {
    const pt = { event: 'submit', toState: 'reviewing' };
    expect(workflowResolvers.WorkflowTriggerResult.pendingTransition({ instance: { pendingTransition: pt } })).toEqual(pt);
    expect(workflowResolvers.WorkflowTriggerResult.pendingTransition({ instance: null })).toBeNull();
    expect(workflowResolvers.WorkflowTriggerResult.pendingTransition({})).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// DraftWorkspace.workflowInstance
// ---------------------------------------------------------------------------

describe('DraftWorkspace.workflowInstance resolver', () => {
  it('loads through context.batch.workflowInstancesBatchLoader with the draft entity', async () => {
    const load = vi.fn().mockResolvedValue({ id: 'inst-id', currentState: 'draft' });
    const batchContext = { ...mockContext, batch: { workflowInstancesBatchLoader: { load } } };
    const draft = { id: 'draft-id', internal_id: 'draft-id' };

    const result = await workflowResolvers.DraftWorkspace.workflowInstance(
      draft,
      {},
      batchContext as any,
    );

    expect(load).toHaveBeenCalledWith(draft);
    expect(result).toEqual({ id: 'inst-id', currentState: 'draft' });
  });

  it('passes the draft entity through unchanged regardless of which id fields are present', async () => {
    const load = vi.fn().mockResolvedValue(null);
    const batchContext = { ...mockContext, batch: { workflowInstancesBatchLoader: { load } } };
    const draft = { internal_id: 'draft-internal-id' };

    await workflowResolvers.DraftWorkspace.workflowInstance(
      draft,
      {},
      batchContext as any,
    );

    expect(load).toHaveBeenCalledWith(draft);
  });
});

// ---------------------------------------------------------------------------
// EntitySetting.workflow_published_version_id
// ---------------------------------------------------------------------------

describe('EntitySetting.workflow_published_version_id resolver', () => {
  it('calls getWorkflowPublishedVersionId with context and entitySetting, and returns the result', async () => {
    const entitySetting = { id: 'es-1', target_type: 'DraftWorkspace', workflow_id: 'wf-id' };
    (getWorkflowPublishedVersionId as any).mockResolvedValue('pub-v1');

    const result = await workflowResolvers.EntitySetting.workflow_published_version_id(
      entitySetting,
      {},
      mockContext,
    );

    expect(getWorkflowPublishedVersionId).toHaveBeenCalledWith(mockContext, entitySetting);
    expect(result).toBe('pub-v1');
  });

  it('returns null when the workflow has never been published', async () => {
    const entitySetting = { id: 'es-1', target_type: 'DraftWorkspace', workflow_id: 'wf-id' };
    (getWorkflowPublishedVersionId as any).mockResolvedValue(null);

    const result = await workflowResolvers.EntitySetting.workflow_published_version_id(
      entitySetting,
      {},
      mockContext,
    );

    expect(result).toBeNull();
  });

  it('returns null when entitySetting has no workflow_id', async () => {
    const entitySetting = { id: 'es-1', target_type: 'DraftWorkspace' };
    (getWorkflowPublishedVersionId as any).mockResolvedValue(null);

    const result = await workflowResolvers.EntitySetting.workflow_published_version_id(
      entitySetting,
      {},
      mockContext,
    );

    expect(getWorkflowPublishedVersionId).toHaveBeenCalledWith(mockContext, entitySetting);
    expect(result).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// WorkflowSerializedTransition field resolvers
// ---------------------------------------------------------------------------

describe('WorkflowSerializedTransition resolver – from field', () => {
  it('should wrap a single string into an array', () => {
    const transition = { from: 'status-open', to: 'status-closed', event: 'close' };
    const result = workflowResolvers.WorkflowSerializedTransition.from(transition);
    expect(result).toEqual(['status-open']);
  });

  it('should return an array unchanged when from is already an array', () => {
    const transition = { from: ['status-open', 'status-draft'], to: 'status-closed', event: 'close' };
    const result = workflowResolvers.WorkflowSerializedTransition.from(transition);
    expect(result).toEqual(['status-open', 'status-draft']);
  });

  it('should return an empty array when from is null', () => {
    const transition = { from: null, to: 'status-closed', event: 'close' };
    const result = workflowResolvers.WorkflowSerializedTransition.from(transition);
    expect(result).toEqual([]);
  });

  it('should return an empty array when from is undefined', () => {
    const transition = { to: 'status-closed', event: 'close' };
    const result = workflowResolvers.WorkflowSerializedTransition.from(transition);
    expect(result).toEqual([]);
  });
});

describe('WorkflowSerializedTransition resolver – to field', () => {
  it('should return the target state when to is defined', () => {
    const transition = { from: ['status-open'], to: 'status-closed', event: 'close' };
    const result = workflowResolvers.WorkflowSerializedTransition.to(transition);
    expect(result).toBe('status-closed');
  });

  it('should return null when to is null (unlinked transition)', () => {
    const transition = { from: ['status-open'], to: null, event: 'close' };
    const result = workflowResolvers.WorkflowSerializedTransition.to(transition);
    expect(result).toBeNull();
  });

  it('should return null when to is undefined', () => {
    const transition = { from: ['status-open'], event: 'close' };
    const result = workflowResolvers.WorkflowSerializedTransition.to(transition);
    expect(result).toBeNull();
  });
});
