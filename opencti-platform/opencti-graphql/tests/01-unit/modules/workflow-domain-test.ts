import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  setWorkflowDefinition,
  isStatusTemplateUsedInWorkflows,
  getAllowedTransitions,
  triggerWorkflowEvent,
} from '../../../src/modules/workflow/domain/workflow-domain';
import { createEntity, loadEntity, updateAttribute } from '../../../src/database/middleware';
import { fullEntitiesList, storeLoadById } from '../../../src/database/middleware-loader';
import { findByType } from '../../../src/modules/entitySetting/entitySetting-domain';
import { validateWorkflowDefinitionData } from '../../../src/modules/workflow/workflow-validation';
import { loadAssignees, loadParticipants } from '../../../src/database/members';
import { extractEntityRepresentativeName } from '../../../src/database/entity-representative';
import { addNotification } from '../../../src/modules/notification/notification-domain';

vi.mock('../../../src/database/middleware', () => ({
  createEntity: vi.fn(),
  createRelation: vi.fn(),
  loadEntity: vi.fn(),
  updateAttribute: vi.fn(),
}));

vi.mock('../../../src/database/middleware-loader', () => ({
  fullEntitiesList: vi.fn(),
  storeLoadById: vi.fn(),
}));

vi.mock('../../../src/modules/entitySetting/entitySetting-domain', () => ({
  findByType: vi.fn(),
}));

vi.mock('../../../src/utils/draftContext', () => ({
  bypassDraftContext: vi.fn((context) => context),
}));

vi.mock('../../../src/modules/workflow/workflow-validation', () => ({
  validateWorkflowDefinitionData: vi.fn().mockResolvedValue({}),
}));

vi.mock('../../../src/database/members', () => ({
  loadAssignees: vi.fn(),
  loadParticipants: vi.fn(),
}));

vi.mock('../../../src/database/entity-representative', () => ({
  extractEntityRepresentativeName: vi.fn().mockReturnValue('Test Entity'),
}));

vi.mock('../../../src/modules/notification/notification-domain', () => ({
  addNotification: vi.fn().mockResolvedValue({}),
}));

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/config/conf')>();
  return {
    ...actual,
    logApp: {
      error: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
    },
  };
});

vi.mock('../../../src/utils/access', () => ({
  SYSTEM_USER: { id: 'system', name: 'system' },
}));

const mockContext = { user: { id: 'ctx-user-id' } } as any;
const mockUser = { id: 'user-id' } as any;

describe('Workflow Domain', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should fail when definition JSON is invalid', async () => {
    (findByType as any).mockResolvedValue({ id: 'entity-setting-id' });

    await expect(setWorkflowDefinition(mockContext, mockUser, 'Incident', '{ invalid-json')).rejects.toThrow('Invalid workflow definition JSON');
    expect(validateWorkflowDefinitionData).not.toHaveBeenCalled();
  });

  it('should fail when entity setting is not found', async () => {
    (findByType as any).mockResolvedValue(null);

    await expect(setWorkflowDefinition(mockContext, mockUser, 'Incident', JSON.stringify({ initialState: 'draft', transitions: [] }))).rejects.toThrow('Entity setting not found for type');
  });

  it('should update existing workflow when entity setting already has workflow id', async () => {
    const definition = JSON.stringify({
      name: 'Updated Workflow',
      initialState: 'draft',
      transitions: [],
    });

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
    (storeLoadById as any).mockResolvedValue({ id: 'workflow-id' });

    await setWorkflowDefinition(mockContext, mockUser, 'Incident', definition);

    expect(validateWorkflowDefinitionData).toHaveBeenCalledWith(mockContext, mockContext.user, definition, 'Incident', 'workflow-id');
    expect(updateAttribute).toHaveBeenCalledWith(
      mockContext,
      mockContext.user,
      'workflow-id',
      'WorkflowDefinition',
      [
        { key: 'workflow_content', value: [definition] },
        { key: 'name', value: ['Updated Workflow'] },
      ],
    );
    expect(createEntity).not.toHaveBeenCalled();
  });

  it('should create and link workflow when no linked workflow exists', async () => {
    const definition = JSON.stringify({
      initialState: 'draft',
      transitions: [],
    });

    (findByType as any).mockResolvedValue({ id: 'entity-setting-id' });
    (createEntity as any).mockResolvedValue({ id: 'workflow-id' });
    (updateAttribute as any).mockResolvedValue({ element: { id: 'entity-setting-id', workflow_id: 'workflow-id' } });

    const result = await setWorkflowDefinition(mockContext, mockUser, 'Incident', definition);

    expect(validateWorkflowDefinitionData).toHaveBeenCalledWith(mockContext, mockContext.user, definition, 'Incident', undefined);
    expect(createEntity).toHaveBeenCalledWith(
      mockContext,
      mockContext.user,
      {
        name: 'Workflow for Incident',
        workflow_content: definition,
      },
      'WorkflowDefinition',
    );
    expect(updateAttribute).toHaveBeenCalledWith(
      mockContext,
      mockContext.user,
      'entity-setting-id',
      'EntitySetting',
      [{ key: 'workflow_id', value: ['workflow-id'] }],
    );
    expect(result).toEqual({ id: 'entity-setting-id', workflow_id: 'workflow-id' });
  });

  it('should return true when status template id is found in string workflow content', async () => {
    (fullEntitiesList as any).mockResolvedValue([
      { workflow_content: '{"states":[{"statusId":"status-template-id"}]}' },
    ]);

    const result = await isStatusTemplateUsedInWorkflows(mockContext, mockUser, 'status-template-id');

    expect(result).toBe(true);
  });

  it('should return true when status template id is found in object workflow content', async () => {
    (fullEntitiesList as any).mockResolvedValue([
      { workflow_content: { states: [{ statusId: 'status-template-id' }] } },
    ]);

    const result = await isStatusTemplateUsedInWorkflows(mockContext, mockUser, 'status-template-id');

    expect(result).toBe(true);
  });

  it('should return false when status template id is not found in any workflow content', async () => {
    (fullEntitiesList as any).mockResolvedValue([
      { workflow_content: '{"states":[{"statusId":"another-id"}]}' },
      { workflow_content: { states: [{ statusId: 'yet-another-id' }] } },
      { workflow_content: null },
    ]);

    const result = await isStatusTemplateUsedInWorkflows(mockContext, mockUser, 'status-template-id');

    expect(result).toBe(false);
  });
});

describe('Transition comments – Domain', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('getAllowedTransitions', () => {
    const definitionWithComments = JSON.stringify({
      initialState: 'draft',
      states: [{ statusId: 'draft' }, { statusId: 'reviewed' }, { statusId: 'published' }],
      transitions: [
        { from: 'draft', to: 'reviewed', event: 'review', comment: 'Requires manager approval' },
        { from: 'reviewed', to: 'published', event: 'publish' },
      ],
    });

    beforeEach(() => {
      (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
        if (id === 'entity-id') return Promise.resolve({ id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' });
        if (id === 'workflow-def-id') return Promise.resolve({ id: 'workflow-def-id', workflow_content: definitionWithComments });
        return Promise.resolve(null);
      });
      (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
    });

    it('should expose the comment field on allowed transitions when comment is defined', async () => {
      (loadEntity as any).mockResolvedValue({ id: 'instance-id', internal_id: 'instance-id', currentState: 'draft', history: '[]' });

      const transitions = await getAllowedTransitions(mockContext, mockUser, 'entity-id');

      expect(transitions).toHaveLength(1);
      expect(transitions[0].event).toBe('review');
      expect(transitions[0].comment).toBe('Requires manager approval');
    });

    it('should expose undefined comment on allowed transitions when no comment is defined', async () => {
      (loadEntity as any).mockResolvedValue({ id: 'instance-id', internal_id: 'instance-id', currentState: 'reviewed', history: '[]' });

      const transitions = await getAllowedTransitions(mockContext, mockUser, 'entity-id');

      expect(transitions).toHaveLength(1);
      expect(transitions[0].event).toBe('publish');
      expect(transitions[0].comment).toBeUndefined();
    });
  });

  describe('triggerWorkflowEvent – comment handling', () => {
    const definitionData = JSON.stringify({
      initialState: 'draft',
      states: [{ statusId: 'draft' }, { statusId: 'reviewed' }],
      transitions: [
        { from: 'draft', to: 'reviewed', event: 'review' },
      ],
    });

    const setupMocks = () => {
      (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
        if (id === 'entity-id') return Promise.resolve({ id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' });
        if (id === 'workflow-def-id') return Promise.resolve({ id: 'workflow-def-id', workflow_content: definitionData });
        return Promise.resolve(null);
      });
      (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
      (loadEntity as any).mockResolvedValue({ id: 'instance-id', internal_id: 'instance-id', currentState: 'draft', history: '[]' });
      (updateAttribute as any).mockResolvedValue({ element: { id: 'instance-id' } });
    };

    const getLastHistoryEntry = () => {
      const updateCall = (updateAttribute as any).mock.calls[0];
      const historyArg = updateCall[4].find((a: any) => a.key === 'history');
      expect(historyArg).toBeDefined();
      return JSON.parse(historyArg.value[0]).at(-1);
    };

    it('should include the user-provided comment in the history entry', async () => {
      setupMocks();

      await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'review', 'Reviewed and approved');

      expect(getLastHistoryEntry().comment).toBe('Reviewed and approved');
    });

    it('should NOT include a comment key in the history entry when no comment is provided', async () => {
      setupMocks();

      await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'review');

      expect(getLastHistoryEntry()).not.toHaveProperty('comment');
    });

    it('should NOT include a comment key in the history entry when comment is an empty string', async () => {
      setupMocks();

      await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'review', '');

      expect(getLastHistoryEntry()).not.toHaveProperty('comment');
    });
  });

  describe('triggerWorkflowEvent – notifications', () => {
    const definitionData = JSON.stringify({
      initialState: 'draft',
      states: [{ statusId: 'draft' }, { statusId: 'reviewed' }],
      transitions: [{ from: 'draft', to: 'reviewed', event: 'review' }],
    });

    const mockEntity = { id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' };

    const setupMocks = () => {
      (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
        if (id === 'entity-id') return Promise.resolve(mockEntity);
        if (id === 'workflow-def-id') return Promise.resolve({ id: 'workflow-def-id', workflow_content: definitionData });
        return Promise.resolve(null);
      });
      (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
      (loadEntity as any).mockResolvedValue({ id: 'instance-id', internal_id: 'instance-id', currentState: 'draft', history: '[]' });
      (updateAttribute as any).mockResolvedValue({ element: { id: 'instance-id' } });
    };

    beforeEach(() => {
      vi.clearAllMocks();
      (addNotification as any).mockResolvedValue({});
      (extractEntityRepresentativeName as any).mockReturnValue('Test Entity');
    });

    it('should call addNotification for each assignee and participant when a comment is provided', async () => {
      setupMocks();
      (loadAssignees as any).mockResolvedValue([{ id: 'assignee-1' }, { id: 'assignee-2' }]);
      (loadParticipants as any).mockResolvedValue([{ id: 'participant-1' }]);

      await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'review', 'My comment');

      expect(addNotification).toHaveBeenCalledTimes(3);
      const calledUserIds = (addNotification as any).mock.calls.map((call: any[]) => call[2].user_id);
      expect(calledUserIds).toContain('assignee-1');
      expect(calledUserIds).toContain('assignee-2');
      expect(calledUserIds).toContain('participant-1');
    });

    it('should NOT call addNotification when no comment is provided', async () => {
      setupMocks();
      (loadAssignees as any).mockResolvedValue([{ id: 'assignee-1' }]);
      (loadParticipants as any).mockResolvedValue([]);

      await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'review');

      expect(addNotification).not.toHaveBeenCalled();
    });

    it('should NOT call addNotification when comment is an empty string', async () => {
      setupMocks();
      (loadAssignees as any).mockResolvedValue([{ id: 'assignee-1' }]);
      (loadParticipants as any).mockResolvedValue([]);

      await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'review', '');

      expect(addNotification).not.toHaveBeenCalled();
    });

    it('should exclude the triggering user from notifications', async () => {
      setupMocks();
      // mockUser has id 'user-id' — also listed as assignee
      (loadAssignees as any).mockResolvedValue([{ id: 'user-id' }, { id: 'other-user' }]);
      (loadParticipants as any).mockResolvedValue([]);

      await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'review', 'My comment');

      expect(addNotification).toHaveBeenCalledTimes(1);
      expect((addNotification as any).mock.calls[0][2].user_id).toBe('other-user');
    });

    it('should deduplicate recipients who are both assignee and participant', async () => {
      setupMocks();
      (loadAssignees as any).mockResolvedValue([{ id: 'shared-user' }]);
      (loadParticipants as any).mockResolvedValue([{ id: 'shared-user' }]);

      await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'review', 'My comment');

      expect(addNotification).toHaveBeenCalledTimes(1);
      expect((addNotification as any).mock.calls[0][2].user_id).toBe('shared-user');
    });

    it('should NOT call addNotification when there are no assignees or participants', async () => {
      setupMocks();
      (loadAssignees as any).mockResolvedValue([]);
      (loadParticipants as any).mockResolvedValue([]);

      await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'review', 'My comment');

      expect(addNotification).not.toHaveBeenCalled();
    });

    it('should include the eventName and comment in the notification message', async () => {
      setupMocks();
      (loadAssignees as any).mockResolvedValue([{ id: 'assignee-1' }]);
      (loadParticipants as any).mockResolvedValue([]);

      await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'review', 'Looks good');

      expect(addNotification).toHaveBeenCalledTimes(1);
      const payload = (addNotification as any).mock.calls[0][2];
      expect(payload.notification_content[0].events[0].message).toBe('[review] Looks good');
    });

    it('should not propagate errors from notification and still return success', async () => {
      setupMocks();
      (loadAssignees as any).mockRejectedValue(new Error('DB error'));
      (loadParticipants as any).mockResolvedValue([]);

      const result = await triggerWorkflowEvent(mockContext, mockUser, 'entity-id', 'review', 'My comment');

      expect(result.success).toBe(true);
      expect(addNotification).not.toHaveBeenCalled();
    });
  });
});
