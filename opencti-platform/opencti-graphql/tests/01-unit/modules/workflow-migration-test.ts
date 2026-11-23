import { beforeEach, describe, expect, it, vi } from 'vitest';
import { logMigration } from '../../../src/config/conf';
import { FunctionalError, LockTimeoutError, UnsupportedError } from '../../../src/config/errors';
import { fullEntitiesList } from '../../../src/database/middleware-loader';
import { StatusScope } from '../../../src/generated/graphql';
import { getAvailableSettings } from '../../../src/modules/entitySetting/entitySetting-utils';
import { getWorkflowConfig, hasOnlyDefaultLegacyStatuses, migrateWorkflowFromStatuses, resolveScopedDefinitionId } from '../../../src/modules/workflow/domain/workflow-domain';
import { NO_LEGACY_STATUSES_MESSAGE } from '../../../src/modules/workflow/migration/status-to-definition-converter';
import { logWorkflowMigrationSummary, migrateAllWorkflowDefinitions, type WorkflowMigrationResult } from '../../../src/modules/workflow/workflow-migration';
import { executionContext, SYSTEM_USER } from '../../../src/utils/access';

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<any>();
  return { ...actual, logMigration: { info: vi.fn(), error: vi.fn(), warn: vi.fn() } };
});
vi.mock('../../../src/database/middleware-loader', () => ({ fullEntitiesList: vi.fn() }));
vi.mock('../../../src/modules/entitySetting/entitySetting-utils', () => ({ getAvailableSettings: vi.fn() }));
vi.mock('../../../src/modules/workflow/domain/workflow-domain', () => ({
  getWorkflowConfig: vi.fn(),
  hasOnlyDefaultLegacyStatuses: vi.fn(),
  migrateWorkflowFromStatuses: vi.fn(),
  resolveScopedDefinitionId: vi.fn(),
}));

const context = executionContext('migration');
const CASE_RFI = 'Case-Rfi';

// Entity settings the platform holds, one per target type
const setEntityTypes = (...types: string[]) => {
  vi.mocked(fullEntitiesList).mockResolvedValue(types.map((target_type) => ({ target_type })) as any);
};
// [entity type, scope] of every migration attempt, in call order
const attempts = () => vi.mocked(migrateWorkflowFromStatuses).mock.calls.map(([, , entityType, , , scope]) => [entityType, scope]);

describe('migrateAllWorkflowDefinitions', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(getAvailableSettings).mockReturnValue(['workflow_id']);
    vi.mocked(getWorkflowConfig).mockResolvedValue({ id: 'entity-setting' } as any);
    vi.mocked(resolveScopedDefinitionId).mockReturnValue(undefined);
    vi.mocked(hasOnlyDefaultLegacyStatuses).mockResolvedValue(false);
    vi.mocked(migrateWorkflowFromStatuses).mockResolvedValue({} as any);
  });

  it('migrates every type with legacy statuses and publishes it', async () => {
    setEntityTypes('Report', 'Grouping');
    const results = await migrateAllWorkflowDefinitions(context, SYSTEM_USER);
    expect(results).toEqual([
      { entityType: 'Report', scope: StatusScope.Global, outcome: 'migrated' },
      { entityType: 'Grouping', scope: StatusScope.Global, outcome: 'migrated' },
    ]);
    expect(migrateWorkflowFromStatuses).toHaveBeenCalledTimes(2);
    expect(migrateWorkflowFromStatuses).toHaveBeenCalledWith(context, SYSTEM_USER, 'Report', true, false, StatusScope.Global);
    expect(migrateWorkflowFromStatuses).toHaveBeenCalledWith(context, SYSTEM_USER, 'Grouping', true, false, StatusScope.Global);
  });

  it('skips a type that already has a workflow (draft only or published)', async () => {
    setEntityTypes('Report', 'Grouping');
    // the definition id is set whether or not that definition has a published version
    vi.mocked(resolveScopedDefinitionId).mockImplementation(((setting: any) => setting.workflow_id) as any);
    vi.mocked(getWorkflowConfig).mockImplementation((async (_ctx: any, _user: any, entityType: string) => (
      entityType === 'Report' ? { workflow_id: 'draft-only-definition' } : { workflow_id: 'published-definition' }
    )) as any);
    const results = await migrateAllWorkflowDefinitions(context, SYSTEM_USER);
    expect(results.map(({ entityType, outcome }) => [entityType, outcome])).toEqual([['Report', 'has_workflow'], ['Grouping', 'has_workflow']]);
    expect(migrateWorkflowFromStatuses).not.toHaveBeenCalled();
  });

  it('skips a type with no legacy statuses', async () => {
    setEntityTypes('Report');
    vi.mocked(migrateWorkflowFromStatuses).mockRejectedValue(FunctionalError(NO_LEGACY_STATUSES_MESSAGE, { entityType: 'Report' }));
    const results = await migrateAllWorkflowDefinitions(context, SYSTEM_USER);
    expect(results).toEqual([{ entityType: 'Report', scope: StatusScope.Global, outcome: 'no_statuses' }]);
  });

  it('leaves a type on its seeded statuses, without publishing a workflow', async () => {
    setEntityTypes('Report', 'Grouping');
    vi.mocked(hasOnlyDefaultLegacyStatuses).mockImplementation(async (_ctx, _user, entityType) => entityType === 'Report');
    const results = await migrateAllWorkflowDefinitions(context, SYSTEM_USER);
    expect(results).toEqual([
      { entityType: 'Report', scope: StatusScope.Global, outcome: 'default_statuses' },
      { entityType: 'Grouping', scope: StatusScope.Global, outcome: 'migrated' },
    ]);
    expect(attempts()).toEqual([['Grouping', StatusScope.Global]]);
  });

  it('only checks the seeded statuses on the GLOBAL scope', async () => {
    setEntityTypes(CASE_RFI);
    vi.mocked(hasOnlyDefaultLegacyStatuses).mockResolvedValue(true);
    const results = await migrateAllWorkflowDefinitions(context, SYSTEM_USER);
    expect(results.map(({ scope, outcome }) => [scope, outcome])).toEqual([
      [StatusScope.Global, 'default_statuses'],
      [StatusScope.RequestAccess, 'migrated'],
    ]);
    expect(hasOnlyDefaultLegacyStatuses).toHaveBeenCalledTimes(1);
  });

  it('reports a business error that is not the no statuses one as failed', async () => {
    setEntityTypes('Report');
    vi.mocked(migrateWorkflowFromStatuses).mockRejectedValue(FunctionalError('Cannot publish migrated workflow: the migrated definition is invalid'));
    const results = await migrateAllWorkflowDefinitions(context, SYSTEM_USER);
    expect(results).toEqual([{
      entityType: 'Report',
      scope: StatusScope.Global,
      outcome: 'failed',
      reason: 'Cannot publish migrated workflow: the migrated definition is invalid',
    }]);
  });

  it('isolates failures per type', async () => {
    setEntityTypes('Report', 'Grouping');
    vi.mocked(migrateWorkflowFromStatuses).mockImplementation((async (_ctx: any, _user: any, entityType: string) => {
      if (entityType === 'Report') throw new Error('boom');
      return {};
    }) as any);
    const results = await migrateAllWorkflowDefinitions(context, SYSTEM_USER);
    expect(results).toEqual([
      { entityType: 'Report', scope: StatusScope.Global, outcome: 'failed', reason: 'boom' },
      { entityType: 'Grouping', scope: StatusScope.Global, outcome: 'migrated' },
    ]);
  });

  it('counts an Enterprise Edition refusal as enterprise_only, not failed nor thrown', async () => {
    setEntityTypes('Report');
    vi.mocked(migrateWorkflowFromStatuses).mockRejectedValue(UnsupportedError('Enterprise edition is not enabled'));
    const results = await migrateAllWorkflowDefinitions(context, SYSTEM_USER);
    expect(results).toEqual([{ entityType: 'Report', scope: StatusScope.Global, outcome: 'enterprise_only', reason: 'Enterprise edition is not enabled' }]);
  });

  it('throws when the entity settings cannot be listed, so the migration is replayed', async () => {
    vi.mocked(fullEntitiesList).mockRejectedValue(new Error('search unavailable'));
    await expect(migrateAllWorkflowDefinitions(context, SYSTEM_USER)).rejects.toThrowError('search unavailable');
  });

  it('a lock failure counts as failed, not thrown', async () => {
    setEntityTypes('Report', 'Grouping');
    vi.mocked(migrateWorkflowFromStatuses).mockImplementation((async (_ctx: any, _user: any, entityType: string) => {
      if (entityType === 'Report') throw LockTimeoutError({ participantIds: ['workflow-migrate:Report'] });
      return {};
    }) as any);
    const results = await migrateAllWorkflowDefinitions(context, SYSTEM_USER);
    expect(results.map(({ entityType, outcome }) => [entityType, outcome])).toEqual([['Report', 'failed'], ['Grouping', 'migrated']]);
    expect(results[0].reason).toContain('Execution timeout');
  });

  it('a failure while reading the entity setting counts as failed, not thrown', async () => {
    setEntityTypes('Report');
    vi.mocked(getWorkflowConfig).mockRejectedValue(new Error('elastic is down'));
    const results = await migrateAllWorkflowDefinitions(context, SYSTEM_USER);
    expect(results).toEqual([{ entityType: 'Report', scope: StatusScope.Global, outcome: 'failed', reason: 'elastic is down' }]);
  });

  it('never migrates DraftWorkspace', async () => {
    setEntityTypes('DraftWorkspace', 'Report');
    const results = await migrateAllWorkflowDefinitions(context, SYSTEM_USER);
    expect(results.map(({ entityType }) => entityType)).toEqual(['Report']);
    expect(attempts()).toEqual([['Report', StatusScope.Global]]);
  });

  it('ignores the types that have no workflow setting', async () => {
    setEntityTypes('IPv4-Addr', 'Report');
    vi.mocked(getAvailableSettings).mockImplementation(((entityType: string) => (
      entityType === 'IPv4-Addr' ? ['platform_hidden_type'] : ['platform_hidden_type', 'workflow_id']
    )) as any);
    const results = await migrateAllWorkflowDefinitions(context, SYSTEM_USER);
    expect(results.map(({ entityType }) => entityType)).toEqual(['Report']);
    expect(attempts()).toEqual([['Report', StatusScope.Global]]);
  });

  it('ignores a type that entity settings do not support', async () => {
    setEntityTypes('Unknown-Type', 'Report');
    vi.mocked(getAvailableSettings).mockImplementation(((entityType: string) => {
      if (entityType === 'Unknown-Type') throw UnsupportedError('This entity type is not support for entity settings');
      return ['workflow_id'];
    }) as any);
    const results = await migrateAllWorkflowDefinitions(context, SYSTEM_USER);
    expect(results.map(({ entityType }) => entityType)).toEqual(['Report']);
  });

  it('migrates the REQUEST_ACCESS scope of Case-Rfi after its GLOBAL scope', async () => {
    setEntityTypes(CASE_RFI, 'Report');
    const results = await migrateAllWorkflowDefinitions(context, SYSTEM_USER);
    expect(attempts()).toEqual([
      [CASE_RFI, StatusScope.Global],
      [CASE_RFI, StatusScope.RequestAccess],
      ['Report', StatusScope.Global],
    ]);
    expect(results.map(({ entityType, scope, outcome }) => [entityType, scope, outcome])).toEqual([
      [CASE_RFI, StatusScope.Global, 'migrated'],
      [CASE_RFI, StatusScope.RequestAccess, 'migrated'],
      ['Report', StatusScope.Global, 'migrated'],
    ]);
  });

  it('keeps the GLOBAL result of Case-Rfi when its REQUEST_ACCESS scope fails', async () => {
    setEntityTypes(CASE_RFI);
    vi.mocked(migrateWorkflowFromStatuses).mockImplementation((async (_ctx: any, _user: any, _entityType: string, _publish: boolean, _overwrite: boolean, scope: StatusScope) => {
      if (scope === StatusScope.RequestAccess) throw new Error('lock timeout');
      return {};
    }) as any);
    const results = await migrateAllWorkflowDefinitions(context, SYSTEM_USER);
    expect(results).toEqual([
      { entityType: CASE_RFI, scope: StatusScope.Global, outcome: 'migrated' },
      { entityType: CASE_RFI, scope: StatusScope.RequestAccess, outcome: 'failed', reason: 'lock timeout' },
    ]);
  });

  it('skips the REQUEST_ACCESS scope of Case-Rfi on Community Edition, without failing', async () => {
    setEntityTypes(CASE_RFI);
    vi.mocked(migrateWorkflowFromStatuses).mockImplementation((async (_ctx: any, _user: any, _entityType: string, _publish: boolean, _overwrite: boolean, scope: StatusScope) => {
      if (scope === StatusScope.RequestAccess) throw UnsupportedError('Enterprise edition is not enabled');
      return {};
    }) as any);
    const results = await migrateAllWorkflowDefinitions(context, SYSTEM_USER);
    expect(results).toEqual([
      { entityType: CASE_RFI, scope: StatusScope.Global, outcome: 'migrated' },
      { entityType: CASE_RFI, scope: StatusScope.RequestAccess, outcome: 'enterprise_only', reason: 'Enterprise edition is not enabled' },
    ]);
  });

  it('checks each scope of Case-Rfi on its own for an existing workflow', async () => {
    setEntityTypes(CASE_RFI);
    vi.mocked(resolveScopedDefinitionId).mockImplementation(((_setting: any, scope: StatusScope) => (
      scope === StatusScope.Global ? 'global-definition' : undefined
    )) as any);
    const results = await migrateAllWorkflowDefinitions(context, SYSTEM_USER);
    expect(results.map(({ scope, outcome }) => [scope, outcome])).toEqual([
      [StatusScope.Global, 'has_workflow'],
      [StatusScope.RequestAccess, 'migrated'],
    ]);
    expect(attempts()).toEqual([[CASE_RFI, StatusScope.RequestAccess]]);
  });

  it('has nothing to migrate when no entity setting exists yet', async () => {
    setEntityTypes();
    expect(await migrateAllWorkflowDefinitions(context, SYSTEM_USER)).toEqual([]);
    expect(migrateWorkflowFromStatuses).not.toHaveBeenCalled();
  });
});

describe('logWorkflowMigrationSummary', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  const result = (entityType: string, outcome: WorkflowMigrationResult['outcome'], scope = StatusScope.Global, reason?: string): WorkflowMigrationResult => (
    { entityType, scope, outcome, ...(reason ? { reason } : {}) }
  );

  it('logs one INFO line with the count of each outcome', () => {
    logWorkflowMigrationSummary([
      result('Report', 'migrated'),
      result('Grouping', 'migrated'),
      result('Note', 'has_workflow'),
      result('Task', 'no_statuses'),
      result('Case', 'no_statuses'),
      result('Opinion', 'no_statuses'),
    ]);
    expect(logMigration.info).toHaveBeenCalledTimes(1);
    expect(vi.mocked(logMigration.info).mock.calls[0][0]).toContain('migrated=2, has_workflow=1, no_statuses=3, default_statuses=0, enterprise_only=0, failed=0');
    expect(logMigration.warn).not.toHaveBeenCalled();
    expect(logMigration.error).not.toHaveBeenCalled();
  });

  it('logs a WARN for failed types', () => {
    logWorkflowMigrationSummary([
      result('Report', 'migrated'),
      result('Grouping', 'failed', StatusScope.Global, 'boom'),
      result('Note', 'failed', StatusScope.Global, 'bang'),
    ]);
    expect(logMigration.info).toHaveBeenCalledTimes(1);
    expect(vi.mocked(logMigration.info).mock.calls[0][0]).toContain('migrated=1, has_workflow=0, no_statuses=0, default_statuses=0, enterprise_only=0, failed=2');
    expect(logMigration.warn).toHaveBeenCalledTimes(1);
    const warning = vi.mocked(logMigration.warn).mock.calls[0][0];
    expect(warning).toContain('Grouping');
    expect(warning).toContain('boom');
    expect(warning).toContain('Note');
    expect(warning).toContain('bang');
    expect(logMigration.error).not.toHaveBeenCalled();
  });

  it('logs a WARN, not an ERROR, with the legacy flow note when a request access scope failed', () => {
    logWorkflowMigrationSummary([
      result('Report', 'failed', StatusScope.Global, 'boom'),
      result('Case-Rfi', 'failed', StatusScope.RequestAccess, 'lock timeout'),
    ]);
    expect(logMigration.warn).toHaveBeenCalledTimes(1);
    const failure = vi.mocked(logMigration.warn).mock.calls[0][0];
    expect(failure).toContain('Report');
    expect(failure).toContain('boom');
    expect(failure).toContain('Case-Rfi');
    expect(failure).toContain('lock timeout');
    expect(failure).toContain('request access flow keeps running on its legacy statuses');
    expect(failure).toContain('migrateWorkflowFromStatuses');
    expect(logMigration.error).not.toHaveBeenCalled();
  });

  it('logs the types that need Enterprise Edition on an INFO line, not as failures', () => {
    logWorkflowMigrationSummary([
      result('Report', 'migrated'),
      result('Case-Rfi', 'enterprise_only', StatusScope.RequestAccess, 'Enterprise edition is not enabled'),
    ]);
    expect(logMigration.info).toHaveBeenCalledTimes(2);
    expect(vi.mocked(logMigration.info).mock.calls[0][0]).toContain('enterprise_only=1, failed=0');
    expect(vi.mocked(logMigration.info).mock.calls[1][0]).toContain('Case-Rfi (REQUEST_ACCESS)');
    expect(logMigration.warn).not.toHaveBeenCalled();
  });

  it('logs no failure line when nothing failed', () => {
    logWorkflowMigrationSummary([]);
    expect(logMigration.info).toHaveBeenCalledTimes(1);
    expect(logMigration.warn).not.toHaveBeenCalled();
    expect(logMigration.error).not.toHaveBeenCalled();
  });
});
