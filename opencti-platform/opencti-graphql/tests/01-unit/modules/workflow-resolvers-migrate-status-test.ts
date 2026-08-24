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
  it('calls the domain migration function (3-arg signature) when scope is GLOBAL', async () => {
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
    );
    expect(result).toBe(mockResult);
  });

  it('rejects with a clear error when scope is RequestAccess (not yet supported)', () => {
    expect(() =>
      workflowResolvers.Mutation.migrateEntityTypeStatusToWorkflowDefinition(
        {},
        { entityType: 'CaseRfi', scope: StatusScope.RequestAccess },
        mockContext,
      ),
    ).toThrow(/Global-scope migration is currently supported/);

    expect(migrateEntityTypeStatusToWorkflowDefinition).not.toHaveBeenCalled();
  });
});
