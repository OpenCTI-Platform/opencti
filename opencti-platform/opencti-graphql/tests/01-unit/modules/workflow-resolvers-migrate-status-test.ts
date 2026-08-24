import { beforeEach, describe, expect, it, vi } from 'vitest';
import workflowResolvers from '../../../src/modules/workflow/api/workflow-resolvers';
import { StatusScope } from '../../../src/generated/graphql';
import { migrateEntityTypeStatusToWorkflowDefinition } from '../../../src/modules/workflow/migration/migrate-status-to-workflow-definition';

vi.mock('../../../src/modules/workflow/migration/migrate-status-to-workflow-definition', () => ({
  migrateEntityTypeStatusToWorkflowDefinition: vi.fn(),
}));

const mockContext = { user: { id: 'user-id' } } as any;

beforeEach(() => {
  vi.clearAllMocks();
});

describe('Mutation resolver – migrateEntityTypeStatusToWorkflowDefinition', () => {
  it('calls the domain migration function with the scope argument when scope is GLOBAL', async () => {
    const mockResult = { entityType: 'Incident', status: 'migrated' };
    vi.mocked(migrateEntityTypeStatusToWorkflowDefinition).mockResolvedValue(mockResult as any);

    const result = await workflowResolvers.Mutation.migrateEntityTypeStatusToWorkflowDefinition(
      {},
      { entityType: 'Incident', scope: StatusScope.Global },
      mockContext,
    );

    expect(migrateEntityTypeStatusToWorkflowDefinition).toHaveBeenCalledWith(
      mockContext,
      mockContext.user,
      'Incident',
      StatusScope.Global,
    );
    expect(result).toBe(mockResult);
  });

  it('calls the domain migration function with the scope argument when scope is RequestAccess', async () => {
    const mockResult = { entityType: 'CaseRfi', status: 'migrated' };
    vi.mocked(migrateEntityTypeStatusToWorkflowDefinition).mockResolvedValue(mockResult as any);

    const result = await workflowResolvers.Mutation.migrateEntityTypeStatusToWorkflowDefinition(
      {},
      { entityType: 'CaseRfi', scope: StatusScope.RequestAccess },
      mockContext,
    );

    expect(migrateEntityTypeStatusToWorkflowDefinition).toHaveBeenCalledWith(
      mockContext,
      mockContext.user,
      'CaseRfi',
      StatusScope.RequestAccess,
    );
    expect(result).toBe(mockResult);
  });
});
