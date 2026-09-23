import { beforeEach, describe, expect, it, vi } from 'vitest';
import { internalDeleteElementById } from '../../../src/database/middleware';
import { fullEntitiesList, internalLoadById } from '../../../src/database/middleware-loader';
import { lockResources } from '../../../src/lock/master-lock';
import { workflowStatusCleanupHandler } from '../../../src/manager/workflowStatusCleanupManager';
import { isStatusOrphaned } from '../../../src/modules/workflow/domain/workflow-domain';

vi.mock('../../../src/database/middleware', () => ({
  internalDeleteElementById: vi.fn(),
}));

vi.mock('../../../src/database/middleware-loader', () => ({
  fullEntitiesList: vi.fn(),
  internalLoadById: vi.fn(),
}));

vi.mock('../../../src/lock/master-lock', () => ({
  lockResources: vi.fn(),
}));

vi.mock('../../../src/modules/workflow/domain/workflow-domain', () => ({
  isStatusOrphaned: vi.fn(),
  getWorkflowStatusLockKey: (entityType: string) => `workflow-status-lifecycle:${entityType}`,
}));

vi.mock('../../../src/utils/access', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/utils/access')>();
  return {
    ...actual,
    executionContext: vi.fn(() => ({ user: { id: 'workflow-manager-user' } })),
  };
});

describe('Workflow status cleanup manager', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (lockResources as any).mockResolvedValue({ unlock: vi.fn() });
  });

  it('should hard-delete a Status that is still orphaned when the grace period has elapsed', async () => {
    const status = { id: 'status-b-id', type: 'Incident', template_id: 'tpl-b', to_be_deleted_at: new Date('2020-01-01') };
    (fullEntitiesList as any).mockResolvedValue([status]);
    (internalLoadById as any).mockResolvedValue(status);
    (isStatusOrphaned as any).mockResolvedValue(true);

    await workflowStatusCleanupHandler();

    expect(lockResources).toHaveBeenCalledWith(['workflow-status-lifecycle:Incident']);
    expect(isStatusOrphaned).toHaveBeenCalledOnce();
    expect(internalDeleteElementById).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      'status-b-id',
      'Status',
    );
  });

  it('should not delete a Status that is no longer orphaned (re-verified during the grace window)', async () => {
    const status = { id: 'status-b-id', type: 'Incident', template_id: 'tpl-b', to_be_deleted_at: new Date('2020-01-01') };
    (fullEntitiesList as any).mockResolvedValue([status]);
    (internalLoadById as any).mockResolvedValue(status);
    (isStatusOrphaned as any).mockResolvedValue(false);

    await workflowStatusCleanupHandler();

    expect(isStatusOrphaned).toHaveBeenCalledOnce();
    expect(internalDeleteElementById).not.toHaveBeenCalled();
  });

  it('should not delete a Status whose deletion mark was cleared by a concurrent republish (race regression)', async () => {
    // The initial list query sees the Status as still past its deadline, but once we acquire the
    // lock and reload it fresh, a republish has cleared to_be_deleted_at in the meantime.
    const staleStatus = { id: 'status-b-id', type: 'Incident', template_id: 'tpl-b', to_be_deleted_at: new Date('2020-01-01') };
    const freshStatus = { id: 'status-b-id', type: 'Incident', template_id: 'tpl-b', to_be_deleted_at: null };
    (fullEntitiesList as any).mockResolvedValue([staleStatus]);
    (internalLoadById as any).mockResolvedValue(freshStatus);

    await workflowStatusCleanupHandler();

    expect(isStatusOrphaned).not.toHaveBeenCalled();
    expect(internalDeleteElementById).not.toHaveBeenCalled();
  });

  it('should continue processing remaining candidates when one deletion fails', async () => {
    (fullEntitiesList as any).mockResolvedValue([
      { id: 'status-a-id', type: 'Incident', template_id: 'tpl-a', to_be_deleted_at: new Date('2020-01-01') },
      { id: 'status-b-id', type: 'Incident', template_id: 'tpl-b', to_be_deleted_at: new Date('2020-01-01') },
    ]);
    (internalLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => Promise.resolve({
      id, type: 'Incident', template_id: 'tpl', to_be_deleted_at: new Date('2020-01-01'),
    }));
    (isStatusOrphaned as any).mockResolvedValue(true);
    (internalDeleteElementById as any)
      .mockRejectedValueOnce(new Error('boom'))
      .mockResolvedValueOnce(undefined);

    await workflowStatusCleanupHandler();

    expect(internalDeleteElementById).toHaveBeenCalledTimes(2);
  });

  it('should do nothing when there are no candidates past their grace period', async () => {
    (fullEntitiesList as any).mockResolvedValue([]);

    await workflowStatusCleanupHandler();

    expect(isStatusOrphaned).not.toHaveBeenCalled();
    expect(internalDeleteElementById).not.toHaveBeenCalled();
  });
});
