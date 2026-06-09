import { describe, it, expect, vi, beforeEach } from 'vitest';
import { validateWorkflowDefinitionData } from '../../../src/modules/workflow/workflow-validation';
import * as middlewareLoader from '../../../src/database/middleware-loader';

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
  // Reset to default mock implementations
  vi.mocked(middlewareLoader.storeLoadById).mockResolvedValue(null as any);
  vi.mocked(middlewareLoader.storeLoadByIds).mockResolvedValue([{ id: 'existing-state' }] as any);
  vi.mocked(middlewareLoader.fullEntitiesList).mockResolvedValue([]);
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

    const errors = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(valid), 'Incident');
    expect(errors).toEqual([]);
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

    const errors = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(valid), 'Incident');
    expect(errors).toEqual([]);
  });

  it('should return error if entity type does not exist', async () => {
    const invalid = {
      initialState: 'test',
      transitions: [],
    };
    const errors = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(invalid), 'NonExistingType');
    expect(errors.length).toBeGreaterThan(0);
    expect(errors.some((e) => e.message.includes("Entity type 'NonExistingType' doesn't exist"))).toBe(true);
  });

  it('should return error if DraftWorkspace does not have validateDraft action', async () => {
    const invalid = {
      initialState: 'existing-state',
      transitions: [
        { from: 'existing-state', to: 'in-progress', event: 'publish', syncActions: [{ type: 'log' }] },
      ],
    };

    const errors = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(invalid), 'DraftWorkspace');
    expect(errors.length).toBeGreaterThan(0);
    expect(errors.some((e) => e.message.includes('DraftWorkspace workflow must contain at least one validateDraft action'))).toBe(true);
  });

  it('should return error if event is duplicated', async () => {
    const invalid = {
      initialState: 'existing-state',
      transitions: [
        { from: 'a', to: 'b', event: 'test' },
        { from: 'a', to: 'c', event: 'test' }, // Change 'b' to 'a' to duplicate from the same source
      ],
    };
    const errors = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(invalid), 'Report');
    expect(errors.length).toBeGreaterThan(0);
    expect(errors.some((e) => e.message.includes("Transition 'test' referenced in multiple transitions"))).toBe(true);
  });

  it('should return error if transition from is null', async () => {
    const invalid = {
      initialState: 'existing-state',
      transitions: [
        { from: null, to: 'b', event: 'test' },
      ],
    };
    const errors = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(invalid), 'Incident');
    expect(errors.length).toBeGreaterThan(0);
    expect(errors.some((e) => e.message.includes('Transition test should be linked to at least one status'))).toBe(true);
  });

  it('should return error if transition to is null', async () => {
    const invalid = {
      initialState: 'existing-state',
      transitions: [
        { from: 'a', to: null, event: 'test' },
      ],
    };
    const errors = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(invalid), 'Incident');
    expect(errors.length).toBeGreaterThan(0);
    expect(errors.some((e) => e.message.includes('Transition test should be linked to at least one status'))).toBe(true);
  });

  it('should return error if filter operator is invalid', async () => {
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
    const errors = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(invalid), 'Incident');
    expect(errors.length).toBeGreaterThan(0);
    expect(errors.some((e) => e.message.includes("Invalid filter operator 'invalid_op'"))).toBe(true);
  });

  it('should return error for invalid JSON', async () => {
    const errors = await validateWorkflowDefinitionData(mockContext, mockUser, '{ invalid json', 'Incident');
    expect(errors.length).toBeGreaterThan(0);
    expect(errors.some((e) => e.type === 'INVALID_JSON')).toBe(true);
  });

  it('should return error for invalid schema', async () => {
    const invalid = {
      // Missing required fields like initialState and transitions
      name: 'Test',
    };
    const errors = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(invalid), 'Incident');
    expect(errors.length).toBeGreaterThan(0);
    expect(errors.some((e) => e.type === 'SCHEMA_VALIDATION_FAILED')).toBe(true);
  });

  it('should return error if filter mode is invalid', async () => {
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
              filters: [{ key: 'status', values: ['test'], mode: 'invalid_mode' }],
              filterGroups: [],
            },
          },
        },
      ],
    };
    const errors = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(invalid), 'Incident');
    expect(errors.length).toBeGreaterThan(0);
    expect(errors.some((e) => e.message.includes("Invalid filter mode 'invalid_mode'"))).toBe(true);
  });

  it('should validate nested filter groups', async () => {
    const valid = {
      initialState: 'existing-state',
      states: [
        { statusId: 'existing-state' },
        { statusId: 'in-progress' },
      ],
      transitions: [
        {
          from: 'existing-state',
          to: 'in-progress',
          event: 'test',
          conditions: {
            filters: {
              mode: 'and',
              filters: [{ key: 'status', values: ['active'] }],
              filterGroups: [
                {
                  mode: 'or',
                  filters: [{ key: 'priority', values: ['high'] }],
                  filterGroups: [],
                },
              ],
            },
          },
        },
      ],
    };
    const errors = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(valid), 'Incident');
    expect(errors).toEqual([]);
  });

  it('should return error for missing filter key', async () => {
    // Schema validation will fail if key is missing (it's required)
    const invalid = {
      initialState: 'existing-state',
      states: [{ statusId: 'existing-state' }],
      transitions: [
        {
          from: 'existing-state',
          to: 'b',
          event: 'test',
          conditions: {
            filters: {
              mode: 'and',
              filters: [{ values: ['test'] }], // Missing key
              filterGroups: [],
            },
          },
        },
      ],
    };
    const errors = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(invalid), 'Incident');
    expect(errors.length).toBeGreaterThan(0);
    // Schema validation fails, so we get SCHEMA_VALIDATION_FAILED
    expect(errors.some((e) => e.type === 'SCHEMA_VALIDATION_FAILED')).toBe(true);
  });

  it('should return error for invalid filter values', async () => {
    // Schema validation will fail if values is not an array (it's required to be array)
    const invalid = {
      initialState: 'existing-state',
      states: [{ statusId: 'existing-state' }],
      transitions: [
        {
          from: 'existing-state',
          to: 'b',
          event: 'test',
          conditions: {
            filters: {
              mode: 'and',
              filters: [{ key: 'status', values: 'not-an-array' }], // values must be array
              filterGroups: [],
            },
          },
        },
      ],
    };
    const errors = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(invalid), 'Incident');
    expect(errors.length).toBeGreaterThan(0);
    // Schema validation fails
    expect(errors.some((e) => e.type === 'SCHEMA_VALIDATION_FAILED')).toBe(true);
  });

  it('should return error for multiple root states', async () => {
    const invalid = {
      initialState: 'state-a',
      states: [
        { statusId: 'state-a' },
        { statusId: 'state-b' },
        { statusId: 'state-c' },
      ],
      transitions: [
        { from: 'state-b', to: 'state-c', event: 'proceed' },
      ],
    };
    const errors = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(invalid), 'Incident');
    expect(errors.length).toBeGreaterThan(0);
    expect(errors.some((e) => e.type === 'MULTIPLE_ROOT_STATES')).toBe(true);
  });

  it('should return error for root state mismatch', async () => {
    // state-b is the root (no incoming transitions), but initialState is state-a
    const invalid = {
      initialState: 'state-a',
      states: [
        { statusId: 'state-a' },
        { statusId: 'state-b' },
      ],
      transitions: [
        { from: 'state-b', to: 'state-a', event: 'proceed' },
      ],
    };
    const errors = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(invalid), 'Incident');
    expect(errors.length).toBeGreaterThan(0);
    expect(errors.some((e) => e.type === 'ROOT_STATE_MISMATCH')).toBe(true);
  });

  it('should handle states with name property', async () => {
    const valid = {
      initialState: 'existing-state',
      states: [
        { name: 'existing-state' },
        { name: 'in-progress' },
      ],
      transitions: [
        { from: 'existing-state', to: 'in-progress', event: 'start' },
      ],
    };
    const errors = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(valid), 'Incident');
    expect(errors).toEqual([]);
  });

  it('should handle wildcard transitions', async () => {
    const valid = {
      initialState: 'existing-state',
      states: [{ statusId: 'existing-state' }],
      transitions: [
        { from: '*', to: 'existing-state', event: 'reset' },
        { from: 'existing-state', to: '*', event: 'any' },
      ],
    };
    const errors = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(valid), 'Incident');
    expect(errors).toEqual([]);
  });

  it('should handle wildcard initialState', async () => {
    const valid = {
      initialState: '*',
      states: [{ statusId: 'existing-state' }],
      transitions: [
        { from: '*', to: 'existing-state', event: 'finish' },
      ],
    };
    const errors = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(valid), 'Incident');
    expect(errors).toEqual([]);
  });

  it('should handle array from states in transitions', async () => {
    const valid = {
      initialState: 'existing-state',
      states: [
        { statusId: 'existing-state' },
        { statusId: 'state-b' },
        { statusId: 'state-c' },
      ],
      transitions: [
        { from: 'existing-state', to: 'state-b', event: 'first' },
        { from: ['existing-state', 'state-b'], to: 'state-c', event: 'merge' },
      ],
    };
    const errors = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(valid), 'Incident');
    expect(errors).toEqual([]);
  });

  it('should return error for duplicate workflow ID', async () => {
    vi.mocked(middlewareLoader.fullEntitiesList).mockReset();
    vi.mocked(middlewareLoader.fullEntitiesList).mockResolvedValue([
      {
        id: 'workflow-1',
        name: 'Existing Workflow',
        draft_version: { id: 'v1', timestamp: '', createdBy: '', content: JSON.stringify({ id: 'my-workflow-id' }), validation_errors: [] },
      } as any,
    ]);

    const invalid = {
      id: 'my-workflow-id',
      initialState: 'existing-state',
      transitions: [],
    };

    const errors = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(invalid), 'Incident');
    expect(errors.length).toBeGreaterThan(0);
    expect(errors.some((e) => e.type === 'DUPLICATE_WORKFLOW_ID')).toBe(true);
  });

  it('should validate states with onEnter actions', async () => {
    const valid = {
      initialState: 'existing-state',
      states: [
        {
          statusId: 'existing-state',
          onEnter: [{ type: 'log', params: { message: 'Entering state' } }],
        },
      ],
      transitions: [],
    };

    const errors = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(valid), 'Incident');
    expect(errors).toEqual([]);
  });

  it('should validate states with onExit actions', async () => {
    const valid = {
      initialState: 'existing-state',
      states: [
        {
          statusId: 'existing-state',
          onExit: [{ type: 'log', params: { message: 'Exiting state' } }],
        },
      ],
      transitions: [],
    };

    const errors = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(valid), 'Incident');
    expect(errors).toEqual([]);
  });

  it('should return error for state in use when removing states', async () => {
    // Reset mocks for this test
    vi.mocked(middlewareLoader.storeLoadById).mockReset();
    vi.mocked(middlewareLoader.fullEntitiesList).mockReset();

    // Mock existing workflow with states
    vi.mocked(middlewareLoader.storeLoadById).mockResolvedValue({
      id: 'existing-workflow',
      draft_version: {
        id: 'v1', timestamp: '', createdBy: '',
        content: JSON.stringify({
          initialState: 'state-a',
          states: [
            { statusId: 'state-a' },
            { statusId: 'state-b' },
          ],
          transitions: [
            { from: 'state-a', to: 'state-b', event: 'proceed' },
          ],
        }),
        validation_errors: [],
      },
    } as any);

    // Mock fullEntitiesList to return different values based on entityTypes
    vi.mocked(middlewareLoader.fullEntitiesList).mockImplementation(
      async (_context: any, _user: any, entityTypes: any): Promise<any> => {
        // First call: WorkflowDefinition (for duplicate ID check)
        if (entityTypes.includes('WorkflowDefinition')) {
          return [];
        }
        // Second call: WorkflowInstance (for state in use check)
        if (entityTypes.includes('WorkflowInstance')) {
          return [
            { id: 'instance-1', workflow_id: 'existing-workflow', currentState: 'state-b' },
          ];
        }
        return [];
      },
    );

    const updated = {
      initialState: 'state-a',
      states: [{ statusId: 'state-a' }], // Removing state-b
      transitions: [],
    };

    const errors = await validateWorkflowDefinitionData(
      mockContext,
      mockUser,
      JSON.stringify(updated),
      'Incident',
      'existing-workflow',
    );

    expect(errors.length).toBeGreaterThan(0);
    expect(errors.some((e) => e.type === 'STATE_IN_USE')).toBe(true);
  });

  it('should allow removing states not in use', async () => {
    // Reset mocks for this test
    vi.mocked(middlewareLoader.storeLoadById).mockReset();
    vi.mocked(middlewareLoader.fullEntitiesList).mockReset();

    // Mock existing workflow with states
    vi.mocked(middlewareLoader.storeLoadById).mockResolvedValue({
      id: 'existing-workflow',
      draft_version: {
        id: 'v1', timestamp: '', createdBy: '',
        content: JSON.stringify({
          initialState: 'state-a',
          states: [
            { statusId: 'state-a' },
            { statusId: 'state-b' },
          ],
          transitions: [
            { from: 'state-a', to: 'state-b', event: 'proceed' },
          ],
        }),
        validation_errors: [],
      },
    } as any);

    // Mock no workflow instances in removed state
    // Both calls return empty arrays
    vi.mocked(middlewareLoader.fullEntitiesList).mockResolvedValue([]);

    const updated = {
      initialState: 'state-a',
      states: [{ statusId: 'state-a' }], // Removing state-b
      transitions: [],
    };

    const errors = await validateWorkflowDefinitionData(
      mockContext,
      mockUser,
      JSON.stringify(updated),
      'Incident',
      'existing-workflow',
    );

    expect(errors).toEqual([]);
  });

  it('should handle existing workflow with invalid JSON', async () => {
    // Reset mocks for this test
    vi.mocked(middlewareLoader.storeLoadById).mockReset();
    vi.mocked(middlewareLoader.fullEntitiesList).mockReset();

    // Mock existing workflow with invalid draft_version content
    vi.mocked(middlewareLoader.storeLoadById).mockResolvedValue({
      id: 'existing-workflow',
      draft_version: { id: 'v1', timestamp: '', createdBy: '', content: '{ invalid json', validation_errors: [] },
    } as any);

    vi.mocked(middlewareLoader.fullEntitiesList).mockResolvedValue([]);

    const updated = {
      initialState: 'state-a',
      states: [{ statusId: 'state-a' }],
      transitions: [],
    };

    const errors = await validateWorkflowDefinitionData(
      mockContext,
      mockUser,
      JSON.stringify(updated),
      'Incident',
      'existing-workflow',
    );

    // Should not crash, just skip state removal validation
    expect(Array.isArray(errors)).toBe(true);
  });

  it('should handle existing workflow without draft_version', async () => {
    // Reset mocks for this test
    vi.mocked(middlewareLoader.storeLoadById).mockReset();
    vi.mocked(middlewareLoader.fullEntitiesList).mockReset();

    // Mock existing workflow with no draft_version (edge case)
    vi.mocked(middlewareLoader.storeLoadById).mockResolvedValue({
      id: 'existing-workflow',
      draft_version: undefined,
    } as any);

    vi.mocked(middlewareLoader.fullEntitiesList).mockResolvedValue([]);

    const updated = {
      initialState: 'state-a',
      states: [{ statusId: 'state-a' }],
      transitions: [],
    };

    const errors = await validateWorkflowDefinitionData(
      mockContext,
      mockUser,
      JSON.stringify(updated),
      'Incident',
      'existing-workflow',
    );

    expect(Array.isArray(errors)).toBe(true);
  });

  // ── asyncActions / syncActions / requiresOrganizationInput ────────────────

  it('should pass with asyncBulkAction in asyncActions', async () => {
    const valid = {
      initialState: 'existing-state',
      states: [{ statusId: 'existing-state' }, { statusId: 'done' }],
      transitions: [
        {
          from: 'existing-state',
          to: 'done',
          event: 'publish',
          asyncActions: [
            {
              type: 'asyncBulkAction',
              params: { scope: 'KNOWLEDGE', actions: [{ type: 'SHARE' }] },
            },
          ],
          syncActions: [{ type: 'validateDraft' }],
          requiresOrganizationInput: true,
        },
      ],
    };
    const result = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(valid), 'DraftWorkspace');
    expect(result).toBeDefined();
  });

  it('should fail when asyncBulkAction is placed in syncActions (wrong mode)', async () => {
    const invalid = {
      initialState: 'existing-state',
      states: [{ statusId: 'existing-state' }, { statusId: 'done' }],
      transitions: [
        {
          from: 'existing-state',
          to: 'done',
          event: 'publish',
          syncActions: [
            { type: 'asyncBulkAction', params: { scope: 'KNOWLEDGE', actions: [{ type: 'SHARE' }] } },
          ],
        },
      ],
    };
    await expect(validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(invalid), 'DraftWorkspace'))
      .rejects.toThrow('not allowed in syncActions');
  });

  it('should detect validateDraft in syncActions for DraftWorkspace requirement', async () => {
    const valid = {
      initialState: 'existing-state',
      states: [{ statusId: 'existing-state' }, { statusId: 'done' }],
      transitions: [
        {
          from: 'existing-state',
          to: 'done',
          event: 'publish',
          asyncActions: [
            { type: 'asyncBulkAction', params: { scope: 'KNOWLEDGE', actions: [{ type: 'SHARE' }] } },
          ],
          syncActions: [{ type: 'validateDraft' }],
        },
      ],
    };
    // Should NOT throw the "must contain at least one validateDraft" error
    const result = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(valid), 'DraftWorkspace');
    expect(result).toBeDefined();
  });

  it('should fail DraftWorkspace validation when validateDraft is absent from all action arrays', async () => {
    const invalid = {
      initialState: 'existing-state',
      states: [{ statusId: 'existing-state' }, { statusId: 'done' }],
      transitions: [
        {
          from: 'existing-state',
          to: 'done',
          event: 'publish',
          asyncActions: [
            { type: 'asyncBulkAction', params: { scope: 'KNOWLEDGE', actions: [{ type: 'SHARE' }] } },
          ],
        },
      ],
    };
    const errors = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(invalid), 'DraftWorkspace');
    expect(errors).toContainEqual(expect.objectContaining({
      type: 'MISSING_VALIDATE_DRAFT_ACTION',
      message: 'DraftWorkspace workflow must contain at least one validateDraft action',
    }));
  });

  it('should fail when unknown action type is used in asyncActions', async () => {
    const invalid = {
      initialState: 'existing-state',
      transitions: [
        {
          from: 'existing-state',
          to: 'done',
          event: 'publish',
          asyncActions: [{ type: 'nonExistentAsyncAction' }],
        },
      ],
    };
    await expect(validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(invalid), 'Incident'))
      .rejects.toThrow("doesn't exist");
  });
});

describe('Workflow Validation – transition comment field', () => {
  it('should pass when transition has no comment (field is optional)', async () => {
    const definition = {
      initialState: 'existing-state',
      states: [{ statusId: 'existing-state' }, { statusId: 'in-progress' }],
      transitions: [
        { from: 'existing-state', to: 'in-progress', event: 'start' },
      ],
    };

    const result = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(definition), 'Incident');
    expect(result).toHaveLength(0);
  });

  it('should pass when transition has a valid comment mode: allowed', async () => {
    const definition = {
      initialState: 'existing-state',
      states: [{ statusId: 'existing-state' }, { statusId: 'in-progress' }],
      transitions: [
        { from: 'existing-state', to: 'in-progress', event: 'start', comment: 'allowed' },
      ],
    };

    const result = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(definition), 'Incident');
    expect(result).toHaveLength(0);
  });

  it('should pass when transition has a valid comment mode: required', async () => {
    const definition = {
      initialState: 'existing-state',
      states: [{ statusId: 'existing-state' }, { statusId: 'in-progress' }],
      transitions: [
        { from: 'existing-state', to: 'in-progress', event: 'start', comment: 'required' },
      ],
    };

    const result = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(definition), 'Incident');
    expect(result).toHaveLength(0);
  });

  it('should pass when transition has a valid comment mode: disabled', async () => {
    const definition = {
      initialState: 'existing-state',
      states: [{ statusId: 'existing-state' }, { statusId: 'in-progress' }],
      transitions: [
        { from: 'existing-state', to: 'in-progress', event: 'start', comment: 'disabled' },
      ],
    };

    const result = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(definition), 'Incident');
    expect(result).toHaveLength(0);
  });

  it('should fail when transition comment mode is invalid', async () => {
    const definition = {
      initialState: 'existing-state',
      states: [{ statusId: 'existing-state' }, { statusId: 'in-progress' }],
      transitions: [
        { from: 'existing-state', to: 'in-progress', event: 'start', comment: 'invalid_mode' },
      ],
    };

    const result = await validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(definition), 'Incident');
    expect(result.some((e) => e.type === 'SCHEMA_VALIDATION_FAILED')).toBe(true);
  });
});
