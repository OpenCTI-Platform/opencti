import { describe, expect, it, vi, beforeEach } from 'vitest';
import { GraphQLError } from 'graphql';
import workflowResolvers from '../../../src/modules/workflow/api/workflow-resolvers';
import {
  getAllowedNextStatuses,
  getAllowedTransitions,
  triggerWorkflowEvent,
} from '../../../src/modules/workflow/domain/workflow-domain';

vi.mock('../../../src/modules/workflow/domain/workflow-domain', () => ({
  getWorkflowDefinition: vi.fn(),
  getWorkflowInstance: vi.fn(),
  getAllowedNextStatuses: vi.fn(),
  getAllowedTransitions: vi.fn(),
  setWorkflowDefinition: vi.fn(),
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
  it('should throw GraphQLError when comment exceeds 5000 characters', async () => {
    const longComment = 'a'.repeat(5001);

    await expect(
      workflowResolvers.Mutation.triggerWorkflowEvent(
        {},
        { entityId: 'entity-id', eventName: 'review', comment: longComment },
        mockContext,
      ),
    ).rejects.toThrow(GraphQLError);

    await expect(
      workflowResolvers.Mutation.triggerWorkflowEvent(
        {},
        { entityId: 'entity-id', eventName: 'review', comment: longComment },
        mockContext,
      ),
    ).rejects.toThrow('Comment exceeds maximum allowed length of 5000 characters.');
  });

  it('should NOT throw when comment is exactly 5000 characters', async () => {
    (triggerWorkflowEvent as any).mockResolvedValue({ success: true, newState: 'reviewed', instance: {}, entity: {} });
    const exactComment = 'a'.repeat(5000);

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

  it('should pass undefined when comment is only spaces (trims to empty string)', async () => {
    (triggerWorkflowEvent as any).mockResolvedValue({ success: true, newState: 'reviewed', instance: {}, entity: {} });

    await workflowResolvers.Mutation.triggerWorkflowEvent(
      {},
      { entityId: 'entity-id', eventName: 'review', comment: '   ' },
      mockContext,
    );

    expect(triggerWorkflowEvent).toHaveBeenCalledWith(
      mockContext, mockContext.user, 'entity-id', 'review', undefined,
    );
  });
});
