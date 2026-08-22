import { beforeEach, describe, expect, it, vi } from 'vitest';
import { logApp } from '../../../src/config/conf';
import { updateAttribute } from '../../../src/database/middleware';
import { fullEntitiesList } from '../../../src/database/middleware-loader';
import { StatusScope } from '../../../src/generated/graphql';
import { projectWorkflowState } from '../../../src/modules/workflow/domain/workflow-projection';

vi.mock('../../../src/database/middleware', () => ({
  updateAttribute: vi.fn(),
}));

vi.mock('../../../src/database/middleware-loader', () => ({
  fullEntitiesList: vi.fn(),
}));

vi.mock('../../../src/config/conf', () => ({
  logApp: { warn: vi.fn(), error: vi.fn(), debug: vi.fn(), info: vi.fn() },
}));

const mockContext = { user: { id: 'ctx-user-id' } } as any;

describe('projectWorkflowState', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should update the entity x_opencti_workflow_id to the Status mapped for that (entity type, scope, state)', async () => {
    (fullEntitiesList as any).mockResolvedValue([
      {
        id: 'status-progress-id', type: 'Incident', scope: StatusScope.Global, template_id: 'tpl-progress', order: 1,
      },
    ]);

    const entity = { id: 'entity-1', internal_id: 'entity-1', entity_type: 'Incident' };
    await projectWorkflowState(mockContext, entity, 'tpl-progress', StatusScope.Global);

    expect(fullEntitiesList).toHaveBeenCalledWith(
      mockContext,
      mockContext.user,
      ['Status'],
      expect.objectContaining({
        filters: expect.objectContaining({
          filters: expect.arrayContaining([
            { key: ['type'], values: ['Incident'] },
            { key: ['scope'], values: [StatusScope.Global] },
            { key: ['template_id'], values: ['tpl-progress'] },
          ]),
        }),
      }),
    );
    expect(updateAttribute).toHaveBeenCalledWith(
      mockContext,
      mockContext.user,
      'entity-1',
      'Incident',
      [{ key: 'x_opencti_workflow_id', value: ['status-progress-id'] }],
      { workflowInternalWrite: true },
    );
  });

  it('should use internal_id over id when both are present', async () => {
    (fullEntitiesList as any).mockResolvedValue([
      {
        id: 'status-id', type: 'Incident', scope: StatusScope.Global, template_id: 'tpl-a', order: 0,
      },
    ]);
    const entity = { id: 'external-id', internal_id: 'internal-id', entity_type: 'Incident' };

    await projectWorkflowState(mockContext, entity, 'tpl-a', StatusScope.Global);

    expect(updateAttribute).toHaveBeenCalledWith(
      mockContext,
      mockContext.user,
      'internal-id',
      'Incident',
      [{ key: 'x_opencti_workflow_id', value: ['status-id'] }],
      { workflowInternalWrite: true },
    );
  });

  it('should log a warning and not call updateAttribute when no Status matches the (entity type, scope, state)', async () => {
    (fullEntitiesList as any).mockResolvedValue([]);
    const entity = { id: 'entity-1', internal_id: 'entity-1', entity_type: 'Incident' };

    await projectWorkflowState(mockContext, entity, 'tpl-unknown', StatusScope.Global);

    expect(updateAttribute).not.toHaveBeenCalled();
    expect(logApp.warn).toHaveBeenCalledOnce();
  });

  it('should not throw when the Status lookup itself fails', async () => {
    (fullEntitiesList as any).mockRejectedValue(new Error('store unavailable'));
    const entity = { id: 'entity-1', internal_id: 'entity-1', entity_type: 'Incident' };

    await expect(projectWorkflowState(mockContext, entity, 'tpl-a', StatusScope.Global)).resolves.toBeUndefined();
    expect(updateAttribute).not.toHaveBeenCalled();
    expect(logApp.warn).toHaveBeenCalledOnce();
  });

  it('Task 8, Step 0.2: should mark its own write as internal so Task 8\'s external-write sync hook never treats it as an external write (anti feedback-loop)', async () => {
    (fullEntitiesList as any).mockResolvedValue([
      {
        id: 'status-progress-id', type: 'Incident', scope: StatusScope.Global, template_id: 'tpl-progress', order: 1,
      },
    ]);
    const entity = { id: 'entity-1', internal_id: 'entity-1', entity_type: 'Incident' };

    await projectWorkflowState(mockContext, entity, 'tpl-progress', StatusScope.Global);

    const [, , , , , opts] = (updateAttribute as any).mock.calls[0];
    expect(opts).toEqual({ workflowInternalWrite: true });
  });
});
