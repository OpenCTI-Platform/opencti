import { beforeEach, describe, expect, it, vi } from 'vitest';
import { internalDeleteElementById } from '../../../src/database/middleware';
import { fullEntitiesList } from '../../../src/database/middleware-loader';
import { workflowStatusCleanupHandler } from '../../../src/manager/workflowStatusCleanupManager';
import { isStatusOrphaned } from '../../../src/modules/workflow/domain/workflow-domain';

vi.mock('../../../src/database/middleware', () => ({
  internalDeleteElementById: vi.fn(),
}));

vi.mock('../../../src/database/middleware-loader', () => ({
  fullEntitiesList: vi.fn(),
}));

vi.mock('../../../src/modules/workflow/domain/workflow-domain', () => ({
  isStatusOrphaned: vi.fn(),
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
  });

  it('should hard-delete a Status that is still orphaned when the grace period has elapsed', async () => {
    (fullEntitiesList as any).mockResolvedValue([
      { id: 'status-b-id', type: 'Incident', template_id: 'tpl-b', to_be_deleted_at: new Date('2020-01-01') },
    ]);
    (isStatusOrphaned as any).mockResolvedValue(true);

    await workflowStatusCleanupHandler();

    expect(isStatusOrphaned).toHaveBeenCalledOnce();
    expect(internalDeleteElementById).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      'status-b-id',
      'Status',
    );
  });

  it('should not delete a Status that is no longer orphaned (re-verified during the grace window)', async () => {
    (fullEntitiesList as any).mockResolvedValue([
      { id: 'status-b-id', type: 'Incident', template_id: 'tpl-b', to_be_deleted_at: new Date('2020-01-01') },
    ]);
    (isStatusOrphaned as any).mockResolvedValue(false);

    await workflowStatusCleanupHandler();

    expect(isStatusOrphaned).toHaveBeenCalledOnce();
    expect(internalDeleteElementById).not.toHaveBeenCalled();
  });

  it('should continue processing remaining candidates when one deletion fails', async () => {
    (fullEntitiesList as any).mockResolvedValue([
      { id: 'status-a-id', type: 'Incident', template_id: 'tpl-a', to_be_deleted_at: new Date('2020-01-01') },
      { id: 'status-b-id', type: 'Incident', template_id: 'tpl-b', to_be_deleted_at: new Date('2020-01-01') },
    ]);
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
