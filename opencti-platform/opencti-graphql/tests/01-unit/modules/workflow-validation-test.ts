import { describe, it, expect, vi } from 'vitest';
import { validateWorkflowDefinitionData } from '../../../src/modules/workflow/workflow-validation';

vi.mock('../../../src/database/middleware-loader', () => ({
  storeLoadByIds: vi.fn().mockResolvedValue([{ id: 'existing-state' }]),
  fullEntitiesList: vi.fn().mockResolvedValue([]),
}));

vi.mock('../../../src/schema/schema-types', async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual as any,
    schemaTypes: {
      ...(actual as any).schemaTypes,
      schemaNames: () => ['DraftWorkspace', 'Incident', 'Report'],
    },
  };
});

vi.mock('../../../src/schema/schema-attributes', async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual as any,
    schemaAttributesDefinition: {
      ...(actual as any).schemaAttributesDefinition,
      getAttributes: () => new Map([['title', {}]]),
    },
  };
});

const mockContext = {} as any;
const mockUser = {} as any;

describe('Workflow Validation', () => {
  it('should pass valid workflow definition', async () => {
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

    await expect(validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(valid), 'Incident')).resolves.toBeDefined();
  });

  it('should fail if entity type does not exist', async () => {
    const valid = {
      initialState: 'test',
      transitions: [],
    };
    await expect(validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(valid), 'NonExistingType')).rejects.toThrow(/Entity type 'NonExistingType' doesn't exist/);
  });

  it('should fail if DraftWorkspace does not have validateDraft action', async () => {
    const invalid = {
      initialState: 'existing-state',
      states: [],
      transitions: [
        { from: 'existing-state', to: 'in-progress', event: 'publish', actions: [{ type: 'log' }] },
      ],
    };

    await expect(validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(invalid), 'DraftWorkspace')).rejects.toThrow('DraftWorkspace workflow must contain at least one validateDraft action');
  });

  it('should fail if event is duplicate', async () => {
    const invalid = {
      initialState: 'existing-state',
      states: [],
      transitions: [
        { from: 'a', to: 'b', event: 'test' },
        { from: 'b', to: 'c', event: 'test' },
      ],
    };
    await expect(validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(invalid), 'Report')).rejects.toThrow("Event 'test' referenced in multiple transitions");
  });

  it('should fail if condition operator is missing when field is present', async () => {
    const invalid = {
      initialState: 'existing-state',
      transitions: [
        { from: 'a', to: 'b', event: 'test', conditions: [{ field: 'title' }] },
      ],
    };
    await expect(validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(invalid), 'Incident')).rejects.toThrow('Condition operator must be provided when field is set');
  });

  it('should fail if condition field is not supported', async () => {
    const invalid = {
      initialState: 'existing-state',
      transitions: [
        { from: 'a', to: 'b', event: 'test', conditions: [{ field: 'unknown', operator: 'eq' }] },
      ],
    };
    // Expected condition failure since 'unknown' is not in getAttributes Map
    await expect(validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(invalid), 'Incident')).rejects.toThrow("Condition field 'unknown' is not supported for entity type 'Incident'");
  });

  it('should fail if action params are invalid', async () => {
    const invalid = {
      initialState: 'existing-state',
      transitions: [
        { from: 'a', to: 'b', event: 'test', actions: [{ type: 'log', params: { message: 123 } }] },
      ],
    };
    await expect(validateWorkflowDefinitionData(mockContext, mockUser, JSON.stringify(invalid), 'Incident')).rejects.toThrow("Invalid params for action 'log'");
  });
});
