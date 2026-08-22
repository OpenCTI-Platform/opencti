import { beforeEach, describe, expect, it, vi } from 'vitest';
import { internalDeleteElementById } from '../../../src/database/middleware';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { notify } from '../../../src/database/redis';
import { statusDelete } from '../../../src/domain/status';
import { findById as findSubTypeById } from '../../../src/domain/subType';
import { publishUserAction } from '../../../src/listener/UserActionListener';
import { validateSetting } from '../../../src/modules/entitySetting/entitySetting-validators';
import { isStatusTemplateUsedInWorkflows } from '../../../src/modules/workflow/domain/workflow-domain';

vi.mock('../../../src/database/middleware', () => ({
  createEntity: vi.fn(),
  deleteElementById: vi.fn(),
  internalDeleteElementById: vi.fn(),
  updateAttribute: vi.fn(),
}));

vi.mock('../../../src/database/middleware-loader', () => ({
  fullEntitiesList: vi.fn(),
  pageEntitiesConnection: vi.fn(),
  storeLoadById: vi.fn(),
  storeLoadByIds: vi.fn(),
}));

vi.mock('../../../src/database/redis', () => ({
  notify: vi.fn(),
  delEditContext: vi.fn(),
  setEditContext: vi.fn(),
}));

vi.mock('../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn(),
}));

vi.mock('../../../src/modules/entitySetting/entitySetting-validators', () => ({
  validateSetting: vi.fn(),
}));

vi.mock('../../../src/modules/workflow/domain/workflow-domain', () => ({
  isStatusTemplateUsedInWorkflows: vi.fn(),
}));

vi.mock('../../../src/domain/subType', () => ({
  findById: vi.fn().mockResolvedValue({ id: 'Incident' }),
}));

describe('statusDelete', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (internalDeleteElementById as any).mockResolvedValue({ element: { id: 'status-id' } });
  });

  it('should throw and not delete when the status is used in a published or draft workflow', async () => {
    (storeLoadById as any).mockResolvedValue({ id: 'status-id', template_id: 'tpl-a' });
    (isStatusTemplateUsedInWorkflows as any).mockResolvedValue(true);

    await expect(statusDelete({} as any, {} as any, 'Incident', 'status-id')).rejects.toThrow(
      'Cannot delete a status that is used in a published or draft workflow',
    );
    expect(internalDeleteElementById).not.toHaveBeenCalled();
    expect(publishUserAction).not.toHaveBeenCalled();
  });

  it('should delete when the status is not used in any workflow', async () => {
    (storeLoadById as any).mockResolvedValue({ id: 'status-id', template_id: 'tpl-a' });
    (isStatusTemplateUsedInWorkflows as any).mockResolvedValue(false);

    await statusDelete({} as any, {} as any, 'Incident', 'status-id');

    expect(internalDeleteElementById).toHaveBeenCalledWith({}, {}, 'status-id', 'Status');
    expect(notify).toHaveBeenCalled();
    expect(findSubTypeById).toHaveBeenCalledWith('Incident');
  });

  it('should still validate the entity setting even when the status no longer exists', async () => {
    (storeLoadById as any).mockResolvedValue(undefined);

    await statusDelete({} as any, {} as any, 'Incident', 'status-id');

    expect(validateSetting).toHaveBeenCalledWith('Incident', 'workflow_configuration');
    expect(isStatusTemplateUsedInWorkflows).not.toHaveBeenCalled();
    expect(internalDeleteElementById).toHaveBeenCalled();
  });
});
