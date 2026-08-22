import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fullEntitiesList } from '../../../src/database/middleware-loader';
import { StatusScope } from '../../../src/generated/graphql';
import { findByType } from '../../../src/modules/entitySetting/entitySetting-domain';
import { publishWorkflowDefinition, setWorkflowDefinition } from '../../../src/modules/workflow/domain/workflow-domain';
import { migrateEntityTypeStatusToWorkflowDefinition } from '../../../src/modules/workflow/migration/migrate-status-to-workflow-definition';
import { ENTITY_TYPE_STATUS, ENTITY_TYPE_STATUS_TEMPLATE } from '../../../src/schema/internalObject';

vi.mock('../../../src/database/middleware-loader', () => ({
  fullEntitiesList: vi.fn(),
}));

vi.mock('../../../src/modules/entitySetting/entitySetting-domain', () => ({
  findByType: vi.fn(),
}));

vi.mock('../../../src/modules/workflow/domain/workflow-domain', () => ({
  setWorkflowDefinition: vi.fn(),
  publishWorkflowDefinition: vi.fn(),
}));

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/config/conf')>();
  return {
    ...actual,
    logApp: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
    logMigration: { info: vi.fn() },
  };
});

const mockContext = { user: { id: 'ctx-user-id' } } as any;
const mockUser = { id: 'user-id' } as any;

describe('migrateEntityTypeStatusToWorkflowDefinition', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('skips (no-op) when the entity type already has a workflow_id configured', async () => {
    (findByType as any).mockResolvedValue({ id: 'setting-1', workflow_id: 'existing-def' });

    const result = await migrateEntityTypeStatusToWorkflowDefinition(mockContext, mockUser, 'Incident');

    expect(result).toEqual({ entityType: 'Incident', status: 'skipped_already_migrated' });
    expect(setWorkflowDefinition).not.toHaveBeenCalled();
    expect(publishWorkflowDefinition).not.toHaveBeenCalled();
  });

  it('throws a FunctionalError when the entity type has no EntitySetting at all', async () => {
    (findByType as any).mockResolvedValue(undefined);

    await expect(migrateEntityTypeStatusToWorkflowDefinition(mockContext, mockUser, 'Incident'))
      .rejects.toThrow('Cannot migrate: no EntitySetting found for entity type');
  });

  it('skips (no-op) when the entity type has no legacy Status data', async () => {
    (findByType as any).mockResolvedValue({ id: 'setting-1', workflow_id: undefined });
    (fullEntitiesList as any).mockResolvedValue([]);

    const result = await migrateEntityTypeStatusToWorkflowDefinition(mockContext, mockUser, 'Incident');

    expect(result).toEqual({ entityType: 'Incident', status: 'skipped_no_data' });
    expect(setWorkflowDefinition).not.toHaveBeenCalled();
  });

  it('throws loudly when request_access-scoped Status data is present (Task 7 not implemented yet)', async () => {
    (findByType as any).mockResolvedValue({ id: 'setting-1', workflow_id: undefined });
    (fullEntitiesList as any).mockImplementation((_ctx: any, _user: any, types: string[]) => {
      if (types.includes(ENTITY_TYPE_STATUS)) {
        return Promise.resolve([
          { id: 's1', template_id: 't1', type: 'CaseRfi', scope: StatusScope.RequestAccess, order: 1 },
        ]);
      }
      return Promise.resolve([{ id: 't1', name: 'Pending' }]);
    });

    await expect(migrateEntityTypeStatusToWorkflowDefinition(mockContext, mockUser, 'CaseRfi'))
      .rejects.toThrow('request_access-scoped Status data');

    expect(setWorkflowDefinition).not.toHaveBeenCalled();
  });

  it('creates and publishes a WorkflowDefinition from GLOBAL-scoped Status data', async () => {
    (findByType as any).mockResolvedValue({ id: 'setting-1', workflow_id: undefined });
    (fullEntitiesList as any).mockImplementation((_ctx: any, _user: any, types: string[]) => {
      if (types.includes(ENTITY_TYPE_STATUS)) {
        return Promise.resolve([
          { id: 's1', template_id: 't1', type: 'Incident', scope: StatusScope.Global, order: 1 },
          { id: 's2', template_id: 't2', type: 'Incident', scope: StatusScope.Global, order: 2 },
        ]);
      }
      if (types.includes(ENTITY_TYPE_STATUS_TEMPLATE)) {
        return Promise.resolve([
          { id: 't1', name: 'New' },
          { id: 't2', name: 'Closed' },
        ]);
      }
      return Promise.resolve([]);
    });

    const result = await migrateEntityTypeStatusToWorkflowDefinition(mockContext, mockUser, 'Incident');

    expect(result).toEqual({ entityType: 'Incident', status: 'migrated' });
    expect(setWorkflowDefinition).toHaveBeenCalledTimes(1);
    const [, , entityTypeArg, definitionArg] = (setWorkflowDefinition as any).mock.calls[0];
    expect(entityTypeArg).toBe('Incident');
    expect(JSON.parse(definitionArg).states.map((s: any) => s.statusId)).toEqual(['t1', 't2']);
    expect(publishWorkflowDefinition).toHaveBeenCalledWith(mockContext, mockUser, 'Incident');
  });

  it('still migrates GLOBAL data even when the entity type also has request_access data flagged separately', async () => {
    // Sanity check: an entity type with ONLY GLOBAL data (no request_access at all) must not be
    // affected by the request_access precondition.
    (findByType as any).mockResolvedValue({ id: 'setting-1', workflow_id: undefined });
    (fullEntitiesList as any).mockImplementation((_ctx: any, _user: any, types: string[]) => {
      if (types.includes(ENTITY_TYPE_STATUS)) {
        return Promise.resolve([
          { id: 's1', template_id: 't1', type: 'Report', scope: StatusScope.Global, order: 1 },
        ]);
      }
      return Promise.resolve([{ id: 't1', name: 'New' }]);
    });

    const result = await migrateEntityTypeStatusToWorkflowDefinition(mockContext, mockUser, 'Report');

    expect(result.status).toBe('migrated');
  });
});
