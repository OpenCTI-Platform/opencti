import { beforeEach, describe, expect, it, vi } from 'vitest';
import { logApp } from '../../../src/config/conf';
import { updateAttribute } from '../../../src/database/middleware';
import { fullEntitiesList } from '../../../src/database/middleware-loader';
import { StatusScope } from '../../../src/generated/graphql';
import { projectWorkflowState, resolveProjectionScope } from '../../../src/modules/workflow/domain/workflow-projection';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../../src/schema/general';
import { schemaTypesDefinition } from '../../../src/schema/schema-types';
import type { BasicStoreEntity } from '../../../src/types/store';

vi.mock('../../../src/database/middleware', () => ({
  updateAttribute: vi.fn(),
}));

vi.mock('../../../src/database/middleware-loader', () => ({
  fullEntitiesList: vi.fn(),
}));

vi.mock('../../../src/config/conf', () => ({
  logApp: { warn: vi.fn(), error: vi.fn(), debug: vi.fn(), info: vi.fn() },
}));

vi.mock('../../../src/utils/draftContext', () => ({
  bypassDraftContext: vi.fn((context) => context),
}));

const mockContext = { user: { id: 'ctx-user-id' } } as any;
const mockUser = { id: 'explicit-user-id' } as any;

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

    const entity = { id: 'entity-1', internal_id: 'entity-1', entity_type: 'Incident' } as BasicStoreEntity;
    await projectWorkflowState(mockContext, mockUser, entity, 'tpl-progress', StatusScope.Global);

    expect(fullEntitiesList).toHaveBeenCalledWith(
      mockContext,
      mockUser,
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
      mockUser,
      'entity-1',
      'Incident',
      [{ key: 'x_opencti_workflow_id', value: ['status-progress-id'] }],
    );
  });

  it('should use internal_id over id when both are present', async () => {
    (fullEntitiesList as any).mockResolvedValue([
      {
        id: 'status-id', type: 'Incident', scope: StatusScope.Global, template_id: 'tpl-a', order: 0,
      },
    ]);
    const entity = { id: 'external-id', internal_id: 'internal-id', entity_type: 'Incident' } as BasicStoreEntity;

    await projectWorkflowState(mockContext, mockUser, entity, 'tpl-a', StatusScope.Global);

    expect(updateAttribute).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      'internal-id',
      'Incident',
      [{ key: 'x_opencti_workflow_id', value: ['status-id'] }],
    );
  });

  it('should fall back to id when internal_id is not present', async () => {
    (fullEntitiesList as any).mockResolvedValue([
      {
        id: 'status-id', type: 'Incident', scope: StatusScope.Global, template_id: 'tpl-a', order: 0,
      },
    ]);
    const entity = { id: 'external-id', entity_type: 'Incident' } as BasicStoreEntity;

    await projectWorkflowState(mockContext, mockUser, entity, 'tpl-a', StatusScope.Global);

    expect(updateAttribute).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      'external-id',
      'Incident',
      [{ key: 'x_opencti_workflow_id', value: ['status-id'] }],
    );
  });

  it('should log a warning and not call updateAttribute when no Status matches the (entity type, scope, state)', async () => {
    (fullEntitiesList as any).mockResolvedValue([]);
    const entity = { id: 'entity-1', internal_id: 'entity-1', entity_type: 'Incident' } as BasicStoreEntity;

    await projectWorkflowState(mockContext, mockUser, entity, 'tpl-unknown', StatusScope.Global);

    expect(updateAttribute).not.toHaveBeenCalled();
    expect(logApp.warn).toHaveBeenCalledOnce();
  });

  it('should not throw when the Status lookup itself fails', async () => {
    (fullEntitiesList as any).mockRejectedValue(new Error('store unavailable'));
    const entity = { id: 'entity-1', internal_id: 'entity-1', entity_type: 'Incident' } as BasicStoreEntity;

    await expect(projectWorkflowState(mockContext, mockUser, entity, 'tpl-a', StatusScope.Global)).resolves.toBeUndefined();
    expect(updateAttribute).not.toHaveBeenCalled();
    expect(logApp.warn).toHaveBeenCalledOnce();
  });

  it('should not throw when the Status is resolved but updateAttribute itself fails', async () => {
    (fullEntitiesList as any).mockResolvedValue([
      {
        id: 'status-id', type: 'Incident', scope: StatusScope.Global, template_id: 'tpl-a', order: 0,
      },
    ]);
    (updateAttribute as any).mockRejectedValue(new Error('update failed'));
    const entity = { id: 'entity-1', internal_id: 'entity-1', entity_type: 'Incident' } as BasicStoreEntity;

    await expect(projectWorkflowState(mockContext, mockUser, entity, 'tpl-a', StatusScope.Global)).resolves.toBeUndefined();
    expect(updateAttribute).toHaveBeenCalledOnce();
    expect(logApp.warn).toHaveBeenCalledOnce();
  });
});

describe('projectWorkflowState – closing reason', () => {
  const entity = { id: 'entity-1', internal_id: 'entity-1', entity_type: 'Incident' } as BasicStoreEntity;

  beforeEach(() => {
    vi.clearAllMocks();
    schemaTypesDefinition.add(ABSTRACT_STIX_DOMAIN_OBJECT, 'Incident');
    (updateAttribute as any).mockResolvedValue({});
    (fullEntitiesList as any).mockResolvedValue([
      {
        id: 'status-closed-id', type: 'Incident', scope: StatusScope.Global, template_id: 'tpl-closed', order: 2,
      },
    ]);
  });

  it('should write the closing reason in the same update as the status', async () => {
    await projectWorkflowState(mockContext, mockUser, entity, 'tpl-closed', StatusScope.Global, 'false-positive');

    expect(updateAttribute).toHaveBeenCalledWith(mockContext, mockUser, 'entity-1', 'Incident', [
      { key: 'x_opencti_workflow_id', value: ['status-closed-id'] },
      { key: 'x_opencti_closing_reason', value: ['false-positive'] },
    ]);
  });

  it('should clear the closing reason when null is given', async () => {
    await projectWorkflowState(mockContext, mockUser, entity, 'tpl-closed', StatusScope.Global, null);

    expect(updateAttribute).toHaveBeenCalledWith(mockContext, mockUser, 'entity-1', 'Incident', [
      { key: 'x_opencti_workflow_id', value: ['status-closed-id'] },
      { key: 'x_opencti_closing_reason', value: [null] },
    ]);
  });

  it('should still write the closing reason when no Status is mapped', async () => {
    (fullEntitiesList as any).mockResolvedValue([]);

    await projectWorkflowState(mockContext, mockUser, entity, 'tpl-unknown', StatusScope.Global, 'duplicate');

    expect(updateAttribute).toHaveBeenCalledWith(mockContext, mockUser, 'entity-1', 'Incident', [
      { key: 'x_opencti_closing_reason', value: ['duplicate'] },
    ]);
  });

  it('should ignore the closing reason for types without the attribute', async () => {
    const draft = { id: 'draft-1', internal_id: 'draft-1', entity_type: 'DraftWorkspace' } as BasicStoreEntity;
    (fullEntitiesList as any).mockResolvedValue([
      {
        id: 'status-draft-id', type: 'DraftWorkspace', scope: StatusScope.Global, template_id: 'tpl-closed', order: 2,
      },
    ]);

    await projectWorkflowState(mockContext, mockUser, draft, 'tpl-closed', StatusScope.Global, null);

    expect(updateAttribute).toHaveBeenCalledWith(mockContext, mockUser, 'draft-1', 'DraftWorkspace', [
      { key: 'x_opencti_workflow_id', value: ['status-draft-id'] },
    ]);
  });
});

describe('resolveProjectionScope', () => {
  it('should default to StatusScope.Global when scope is undefined', () => {
    expect(resolveProjectionScope(undefined)).toBe(StatusScope.Global);
  });

  it("should default to StatusScope.Global when scope is 'standard'", () => {
    expect(resolveProjectionScope('standard')).toBe(StatusScope.Global);
  });

  it('should pass through an explicit non-standard scope as-is', () => {
    expect(resolveProjectionScope(StatusScope.RequestAccess)).toBe(StatusScope.RequestAccess);
  });
});
