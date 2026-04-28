import { beforeEach, describe, expect, it, vi } from 'vitest';
import { setWorkflowDefinition, isStatusTemplateUsedInWorkflows } from '../../../src/modules/workflow/domain/workflow-domain';
import { createEntity, updateAttribute } from '../../../src/database/middleware';
import { fullEntitiesList, storeLoadById } from '../../../src/database/middleware-loader';
import { findByType } from '../../../src/modules/entitySetting/entitySetting-domain';
import { validateWorkflowDefinitionData } from '../../../src/modules/workflow/workflow-validation';

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