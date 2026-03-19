import { vi, describe, it, expect, beforeEach } from 'vitest';
import { addDraftWorkspace } from '../../../src/modules/draftWorkspace/draftWorkspace-domain';
import * as middleware from '../../../src/database/middleware';
import * as accessModule from '../../../src/utils/authorizedMembers';
import * as telemetryManager from '../../../src/manager/telemetryManager';
import * as redis from '../../../src/database/redis';

vi.mock('../../../src/database/middleware');
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
            expect.objectContaining({ id: 'user2', access_right: 'view' }), // groups_restriction_ids implicitely removed
            expect.objectContaining({ id: 'user3', access_right: 'admin', groups_restriction_ids: ['group1'] }),
        ]),
      }),
      expect.anything()
    );
    // Ensure groups_restriction_ids is removed for user2
    const callArgs = vi.mocked(middleware.createEntity).mock.calls[0][2];
    const user2Member = callArgs.authorized_members.find((m: any) => m.id === 'user2');
    expect(user2Member.groups_restriction_ids).toBeUndefined();
  });

  it('should throw if authorized members do not contain valid admin', async () => {
    vi.spyOn(accessModule, 'containsValidAdmin').mockResolvedValue(false);

    const input = {
      name: 'Draft No Admin',
      authorized_members: [
        { id: 'user2', access_right: 'view' },
      ],
    };

    await expect(addDraftWorkspace(mockContext, mockUser, input))
      .rejects
      .toThrow('It should have at least one valid member with admin access');
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
            name: 'Simple Draft'
        }),
        expect.anything()
    );
  });
});
