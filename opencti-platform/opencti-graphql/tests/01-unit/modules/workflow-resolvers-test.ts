import { describe, expect, it, vi, beforeEach } from 'vitest';
import workflowResolvers from '../../../src/modules/workflow/api/workflow-resolvers';
import { getAllowedNextStatuses, getAllowedTransitions, triggerWorkflowEvent } from '../../../src/modules/workflow/domain/workflow-domain';
import type { AuthContext } from '../../../src/types/user';
import * as workflowDomain from '../../../src/modules/workflow/domain/workflow-domain';

// Mock all workflow domain functions
vi.mock('../../../src/modules/workflow/domain/workflow-domain', () => ({
  getWorkflowDefinition: vi.fn(),
  getWorkflowInstance: vi.fn(),
  getAllowedNextStatuses: vi.fn(),
  getAllowedTransitions: vi.fn(),
  setWorkflowDefinition: vi.fn(),
  publishWorkflowDefinition: vi.fn(),
  deleteWorkflowDefinition: vi.fn(),
  triggerWorkflowEvent: vi.fn(),
}));

const mockContext = { user: { id: 'user-id' } } as any;

beforeEach(() => {
  vi.clearAllMocks();
});

// ---------------------------------------------------------------------------
// WorkflowTransition field resolver
// ---------------------------------------------------------------------------

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
    );
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
    const triggerResult = { newState: 'reviewed', instance: {}, entity: {} };
    const status = workflowResolvers.WorkflowTriggerResult.status(triggerResult);
    expect(status).toEqual({ id: 'reviewed', template_id: 'reviewed' });
  });

  it('should return null when newState is absent', () => {
    const triggerResult = { instance: {}, entity: {} };
    const status = workflowResolvers.WorkflowTriggerResult.status(triggerResult);
    expect(status).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Query.allowedNextStatuses
// ---------------------------------------------------------------------------

describe('Query.allowedNextStatuses resolver', () => {
  it('should delegate to getAllowedNextStatuses and return the result', async () => {
    const mockStatuses = [
      { id: 'status-2', template_id: 'status-2' },
      { id: 'status-3', template_id: 'status-3' },
    ];
    (getAllowedNextStatuses as any).mockResolvedValue(mockStatuses);

    const result = await workflowResolvers.Query.allowedNextStatuses({}, { entityId: 'entity-id' }, mockContext);

    expect(getAllowedNextStatuses).toHaveBeenCalledWith(mockContext, mockContext.user, 'entity-id');
    expect(result).toEqual(mockStatuses);
  });

  it('should return an empty array when no next statuses are available', async () => {
    (getAllowedNextStatuses as any).mockResolvedValue([]);

    const result = await workflowResolvers.Query.allowedNextStatuses({}, { entityId: 'entity-id' }, mockContext);

    expect(result).toEqual([]);
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
      mockContext, mockContext.user, 'entity-id', 'review', exactComment,
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
      mockContext, mockContext.user, 'entity-id', 'review', 'trimmed comment',
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
      mockContext, mockContext.user, 'entity-id', 'review', undefined,
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
        );
        expect(result).toBe(mockDefinition);
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

    describe('allowedNextStatuses', () => {
      it('should call getAllowedNextStatuses with correct arguments', async () => {
        const mockStatuses = ['in-progress', 'closed'];
        vi.mocked(workflowDomain.getAllowedNextStatuses).mockResolvedValue(mockStatuses);

        const result = await workflowResolvers.Query.allowedNextStatuses(
          {},
          { entityId: 'entity-456' },
          mockContext,
        );

        expect(workflowDomain.getAllowedNextStatuses).toHaveBeenCalledWith(
          mockContext,
          mockContext.user,
          'entity-456',
        );
        expect(result).toBe(mockStatuses);
      });
    });

    describe('allowedTransitions', () => {
      it('should call getAllowedTransitions with correct arguments', async () => {
        const mockTransitions = [{ event: 'close', toState: 'closed', actions: [] }];
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
        );
        expect(result).toBe(mockDeleted);
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
      it('should return status object with id and template_id', () => {
        const instance = { currentState: 'open' };
        const result = workflowResolvers.WorkflowInstance.currentStatus(instance);
        expect(result).toEqual({ id: 'open', template_id: 'open' });
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
        const transition = { toState: 'closed' };
        const result = workflowResolvers.WorkflowTransition.toStatus(transition);
        expect(result).toEqual({ id: 'closed', template_id: 'closed' });
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
        const result = { newState: 'completed' };
        const status = workflowResolvers.WorkflowTriggerResult.status(result);
        expect(status).toEqual({ id: 'completed', template_id: 'completed' });
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
      it('should call getWorkflowInstance with draft id', async () => {
        const mockInstance = { id: 'inst-2', currentState: 'draft' };
        vi.mocked(workflowDomain.getWorkflowInstance).mockResolvedValue(mockInstance);

        const draft = { id: 'draft-123' };
        const result = await workflowResolvers.DraftWorkspace.workflowInstance(
          draft,
          {},
          mockContext,
        );

        expect(workflowDomain.getWorkflowInstance).toHaveBeenCalledWith(
          mockContext,
          mockContext.user,
          'draft-123',
        );
        expect(result).toBe(mockInstance);
      });

      it('should call getWorkflowInstance with internal_id when id is not present', async () => {
        const mockInstance = { id: 'inst-3', currentState: 'draft' };
        vi.mocked(workflowDomain.getWorkflowInstance).mockResolvedValue(mockInstance);

        const draft = { internal_id: 'internal-draft-456' };
        const result = await workflowResolvers.DraftWorkspace.workflowInstance(
          draft,
          {},
          mockContext,
        );

        expect(workflowDomain.getWorkflowInstance).toHaveBeenCalledWith(
          mockContext,
          mockContext.user,
          'internal-draft-456',
        );
        expect(result).toBe(mockInstance);
      });
    });
  });

  describe('EntitySetting type resolvers', () => {
    describe('errors', () => {
      it('should return errors when present', () => {
        const errors = [{ message: 'Invalid transition' }];
        const entitySetting = { errors };
        const result = workflowResolvers.EntitySetting.errors(entitySetting);
        expect(result).toBe(errors);
      });

      it('should return empty array when errors is not present', () => {
        const entitySetting = {};
        const result = workflowResolvers.EntitySetting.errors(entitySetting);
        expect(result).toEqual([]);
      });

      it('should return empty array when errors is null', () => {
        const entitySetting = { errors: null };
        const result = workflowResolvers.EntitySetting.errors(entitySetting);
        expect(result).toEqual([]);
      });
    });
  });
});
