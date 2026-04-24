import { describe, it, expect, vi, beforeEach } from 'vitest';
import { validateWorkflowDefinitionData } from '../../../src/modules/workflow/workflow-validation';

vi.mock('../../../src/database/middleware-loader', () => ({
  storeLoadById: vi.fn().mockResolvedValue(null),
  storeLoadByIds: vi.fn().mockResolvedValue([{ id: 'existing-state' }]),
  fullEntitiesList: vi.fn().mockResolvedValue([]),
}));

vi.mock('../../../src/database/engine', () => ({
  elList: vi.fn().mockResolvedValue([]),
  elIndexExists: vi.fn().mockResolvedValue(false),
}));

vi.mock('../../../src/schema/stixCoreObject', () => ({
  isBasicObject: vi.fn((type) => ['Incident', 'Report'].includes(type)),
}));

vi.mock('../../../src/schema/schemaUtils', () => ({
  getParentTypes: vi.fn().mockReturnValue([]),
  getAttributes: vi.fn().mockReturnValue(new Map()),
}));

const mockContext = {} as any;
const mockUser = {
  id: 'user-1',
  user_email: 'test@example.com',
  roles: [],
  groups: [],
  organizations: [],
  allowed_marking: [],
  effective_confidence_level: {},
  capabilities: [],
} as any;

beforeEach(() => {
  vi.clearAllMocks();
});

describe('Workflow Validation', () => {
  it('should pass valid workflow definition without conditions', async () => {
    const valid = {
      id: 'valid-id',
      name: 'Valid Workflow',
      initialState: 'existing-state',
      states: [
        { statusId: 'existing-state' },
        { statusId: 'in-progress' },
      ],
      transitions: [
        { from: 'existing-state', to: 'in-progress', event: 'start' },
      ],
    };

    const result = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(valid), 'Incident');
    expect(result).toBeDefined();
  });

  it('should pass valid workflow definition with FilterGroup conditions', async () => {
    const valid = {
      id: 'valid-id',
      name: 'Valid Workflow',
      initialState: 'existing-state',
      states: [
        { statusId: 'existing-state' },
        { statusId: 'in-progress' },
      ],
      transitions: [
        {
          from: 'existing-state',
          to: 'in-progress',
          event: 'start',
          conditions: {
            filters: {
              mode: 'and',
              filters: [
                { key: 'status', values: ['active'], operator: 'eq' },
              ],
              filterGroups: [],
            },
          },
        },
      ],
    };

    const result = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(valid), 'Incident');
    expect(result).toBeDefined();
  });

  it('should fail if entity type does not exist', async () => {
    const invalid = {
      initialState: 'test',
      transitions: [],
    };
    await expect(validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(invalid), 'NonExistingType')).rejects.toThrow("Entity type 'NonExistingType' doesn't exist");
  });

  it('should fail if DraftWorkspace does not have validateDraft action', async () => {
    const invalid = {
      initialState: 'existing-state',
      transitions: [
        { from: 'existing-state', to: 'in-progress', event: 'publish', actions: [{ type: 'log' }] },
      ],
    };

    await expect(validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(invalid), 'DraftWorkspace')).rejects.toThrow('DraftWorkspace workflow must contain at least one validateDraft action');
  });

  it('should fail if event is duplicated', async () => {
    const invalid = {
      initialState: 'existing-state',
      transitions: [
        { from: 'a', to: 'b', event: 'test' },
        { from: 'b', to: 'c', event: 'test' },
      ],
    };
    await expect(validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(invalid), 'Report')).rejects.toThrow("Transition 'test' referenced in multiple transitions");
  });

  it('should fail if transition from is null', async () => {
    const invalid = {
      initialState: 'existing-state',
      transitions: [
        { from: null, to: 'b', event: 'test' },
      ],
    };
    await expect(validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(invalid), 'Incident')).rejects.toThrow('Transition test should be linked to at least one status');
  });

  it('should fail if transition to is null', async () => {
    const invalid = {
      initialState: 'existing-state',
      transitions: [
        { from: 'a', to: null, event: 'test' },
      ],
    };
    await expect(validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(invalid), 'Incident')).rejects.toThrow('Transition test should be linked to at least one status');
  });

  it('should fail if filter operator is invalid', async () => {
    const invalid = {
      initialState: 'existing-state',
      transitions: [
        {
          from: 'a',
          to: 'b',
          event: 'test',
          conditions: {
            filters: {
              mode: 'and',
              filters: [{ key: 'status', values: ['test'], operator: 'invalid_op' }],
              filterGroups: [],
            },
          },
        },
      ],
    };
    await expect(validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(invalid), 'Incident')).rejects.toThrow("Invalid filter operator 'invalid_op'");
  });
});
