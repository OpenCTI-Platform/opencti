import { vi, describe, it, expect, beforeEach } from 'vitest';
import { addDraftWorkspace, draftWorkspacesNumber } from '../../../src/modules/draftWorkspace/draftWorkspace-domain';
import * as middleware from '../../../src/database/middleware';
import * as middlewareLoader from '../../../src/database/middleware-loader';
import * as engine from '../../../src/database/engine';
import * as draftContextUtils from '../../../src/utils/draftContext';
import * as accessModule from '../../../src/utils/authorizedMembers';
import * as telemetryManager from '../../../src/manager/telemetryManager';
import * as redis from '../../../src/database/redis';
import { WORKFLOW_INSTANCE_STATUS_FILTER } from '../../../src/utils/filtering/filtering-constants';
import { ENTITY_TYPE_WORKFLOW_INSTANCE } from '../../../src/modules/workflow/types/workflow-types';

vi.mock('../../../src/database/middleware');
vi.mock('../../../src/database/middleware-loader');
vi.mock('../../../src/database/engine');
vi.mock('../../../src/manager/telemetryManager');
vi.mock('../../../src/database/redis');

// Mock context and user
const mockUser: any = {
  id: 'user1',
  name: 'User One',
};
const mockContext: any = {
  user: mockUser,
};

describe('addDraftWorkspace', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.spyOn(accessModule, 'sanitizeAuthorizedMembers').mockImplementation((input) => input);
    vi.spyOn(accessModule, 'containsValidAdmin').mockResolvedValue(true);
    vi.spyOn(middleware, 'createEntity').mockResolvedValue({ id: 'draft-1', name: 'Draft 1' });
    vi.spyOn(telemetryManager, 'addDraftCreationCount').mockResolvedValue();
    vi.spyOn(redis, 'notify').mockResolvedValue(undefined);
  });

  it('should create draft workspace with sanitized authorized members', async () => {
    const input = {
      name: 'Test Draft',
      authorized_members: [
        { id: 'user2', access_right: 'view', groups_restriction_ids: [] },
        { id: 'user3', access_right: 'admin', groups_restriction_ids: ['group1'] },
      ],
    };

    // sanitized members should have empty groups restriction removed
    await addDraftWorkspace(mockContext, mockUser, input);

    expect(middleware.createEntity).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.objectContaining({
        authorized_members: expect.arrayContaining([
          expect.objectContaining({ id: 'user2', access_right: 'view' }), // groups_restriction_ids implicitly removed
          expect.objectContaining({ id: 'user3', access_right: 'admin', groups_restriction_ids: ['group1'] }),
        ]),
      }),
      'DraftWorkspace',
      expect.objectContaining({ bypassMandatoryAttributes: false }),
    );
    // Ensure groups_restriction_ids is removed for user2
    const callArgs = vi.mocked(middleware.createEntity).mock.calls[0][2];
    const user2Member = callArgs.authorized_members.find((m: any) => m.id === 'user2');
    expect(user2Member.groups_restriction_ids).toBeUndefined();
  });

  it('should not throw if authorized members do not contain valid admin', async () => {
    vi.spyOn(accessModule, 'containsValidAdmin').mockResolvedValue(false);

    const input = {
      name: 'Draft No Admin',
      authorized_members: [
        { id: 'user2', access_right: 'view' },
      ],
    };

    await expect(addDraftWorkspace(mockContext, mockUser, input))
      .resolves
      .not
      .toThrow();
  });

  it('should allow creation without authorized members', async () => {
    const input = {
      name: 'Simple Draft',
    };

    await addDraftWorkspace(mockContext, mockUser, input);

    expect(middleware.createEntity).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.objectContaining({
        name: 'Simple Draft',
      }),
      'DraftWorkspace',
      expect.objectContaining({ bypassMandatoryAttributes: false }),
    );
  });
});

describe('resolveWorkflowInstanceStatusFilter (via draftWorkspacesNumber)', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.spyOn(engine, 'elCount').mockResolvedValue(0);
    vi.spyOn(draftContextUtils, 'bypassDraftContext').mockReturnValue(mockContext);
  });

  it('should not call fullEntitiesList when no workflowInstanceCurrentState filter is present', async () => {
    const args = {
      filters: {
        mode: 'and',
        filters: [{ key: 'name', values: ['my-draft'], operator: 'eq', mode: 'or' }],
        filterGroups: [],
      },
    };
    await draftWorkspacesNumber(mockContext, mockUser, args);
    expect(middlewareLoader.fullEntitiesList).not.toHaveBeenCalled();
  });

  it('should replace workflowInstanceCurrentState filter with matching entity ids', async () => {
    vi.spyOn(middlewareLoader, 'fullEntitiesList').mockResolvedValue([
      { entity_id: 'draft-uuid-1' },
      { entity_id: 'draft-uuid-2' },
    ] as any);
    const args = {
      filters: {
        mode: 'and',
        filters: [{ key: WORKFLOW_INSTANCE_STATUS_FILTER, values: ['status-template-abc'], operator: 'eq', mode: 'or' }],
        filterGroups: [],
      },
    };
    await draftWorkspacesNumber(mockContext, mockUser, args);
    expect(middlewareLoader.fullEntitiesList).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      [ENTITY_TYPE_WORKFLOW_INSTANCE],
      expect.objectContaining({
        filters: expect.objectContaining({
          filters: expect.arrayContaining([
            expect.objectContaining({ key: ['currentState'], values: ['status-template-abc'] }),
          ]),
        }),
      }),
    );
    expect(engine.elCount).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.anything(),
      expect.objectContaining({
        filters: expect.objectContaining({
          filters: expect.arrayContaining([
            expect.objectContaining({ key: ['id'], values: ['draft-uuid-1', 'draft-uuid-2'] }),
          ]),
        }),
      }),
    );
  });

  it('should use <no-match> fallback when no WorkflowInstance entities match the filter', async () => {
    vi.spyOn(middlewareLoader, 'fullEntitiesList').mockResolvedValue([] as any);
    const args = {
      filters: {
        mode: 'and',
        filters: [{ key: WORKFLOW_INSTANCE_STATUS_FILTER, values: ['status-template-xyz'], operator: 'eq', mode: 'or' }],
        filterGroups: [],
      },
    };
    await draftWorkspacesNumber(mockContext, mockUser, args);
    expect(engine.elCount).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.anything(),
      expect.objectContaining({
        filters: expect.objectContaining({
          filters: expect.arrayContaining([
            expect.objectContaining({ key: ['id'], values: ['<no-match>'] }),
          ]),
        }),
      }),
    );
  });
});
