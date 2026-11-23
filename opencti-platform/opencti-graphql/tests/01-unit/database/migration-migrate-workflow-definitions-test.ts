import { beforeEach, describe, expect, it, vi } from 'vitest';
import { up } from '../../../src/migrations/1795449700000-migrate-workflow-definitions';
import { logMigration } from '../../../src/config/conf';
import { StatusScope } from '../../../src/generated/graphql';
import { logWorkflowMigrationSummary, migrateAllWorkflowDefinitions } from '../../../src/modules/workflow/workflow-migration';
import { SYSTEM_USER } from '../../../src/utils/access';

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<any>();
  return { ...actual, logMigration: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() } };
});
vi.mock('../../../src/utils/access', async (importOriginal) => {
  const actual = await importOriginal<any>();
  return { ...actual, executionContext: vi.fn(() => ({ source: 'migration' })) };
});
vi.mock('../../../src/modules/workflow/workflow-migration', () => ({
  migrateAllWorkflowDefinitions: vi.fn(),
  logWorkflowMigrationSummary: vi.fn(),
}));

const runMigration = async () => {
  const next = vi.fn();
  await up(next);
  return next;
};

describe('migration migrate-workflow-definitions', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('should migrate the workflow definitions, log the summary, then continue', async () => {
    const results = [{ entityType: 'Report', scope: StatusScope.Global, outcome: 'migrated' }];
    vi.mocked(migrateAllWorkflowDefinitions).mockResolvedValue(results as any);
    const next = await runMigration();
    expect(migrateAllWorkflowDefinitions).toHaveBeenCalledWith({ source: 'migration' }, SYSTEM_USER);
    expect(logWorkflowMigrationSummary).toHaveBeenCalledWith(results);
    expect(vi.mocked(migrateAllWorkflowDefinitions).mock.invocationCallOrder[0])
      .toBeLessThan(vi.mocked(logWorkflowMigrationSummary).mock.invocationCallOrder[0]);
    expect(next).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenCalledWith();
  });

  it('should fail the migration so it is replayed on the next start when the migration itself fails', async () => {
    const error = new Error('elastic is down');
    vi.mocked(migrateAllWorkflowDefinitions).mockRejectedValue(error);
    const next = await runMigration();
    expect(logWorkflowMigrationSummary).not.toHaveBeenCalled();
    expect(vi.mocked(logMigration.error).mock.calls.map(([message]) => message).join('\n')).toContain('replayed on the next start');
    expect(next).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenCalledWith(error);
  });

  it('should wrap a non-Error rejection before failing the migration', async () => {
    vi.mocked(migrateAllWorkflowDefinitions).mockRejectedValue('lock timeout');
    const next = await runMigration();
    expect(next).toHaveBeenCalledTimes(1);
    expect(next.mock.calls[0][0]).toBeInstanceOf(Error);
    expect(next.mock.calls[0][0].message).toBe('lock timeout');
  });
});
