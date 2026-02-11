import { describe, it, expect, vi, beforeEach } from 'vitest';
import { addUserToken, revokeUserToken } from '../../../../src/modules/user/user-domain';
import { updateAttribute } from '../../../../src/database/middleware';
import { publishUserAction } from '../../../../src/listener/UserActionListener';
import { ENTITY_TYPE_USER } from '../../../../src/schema/internalObject';
import { TokenDuration } from '../../../../src/generated/graphql';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import { isUserHasCapability } from '../../../../src/utils/access';

vi.mock('../../../../src/utils/access', async () => {
  const actual: any = await vi.importActual('../../../../src/utils/access');
  return {
    ...actual,
    isUserHasCapability: vi.fn(),
  };
});

vi.mock('../../../../src/database/middleware', () => ({
  updateAttribute: vi.fn().mockResolvedValue({ element: { id: 'user-id' } }),
}));
vi.mock('../../../../src/listener/UserActionListener');
vi.mock('../../../../src/database/redis', () => ({
  notify: vi.fn(),
}));
vi.mock('../../../../src/database/middleware-loader', () => ({
  internalLoadById: vi.fn(),
}));
import { internalLoadById } from '../../../../src/database/middleware-loader';
import { notify } from '../../../../src/database/redis';

describe('User Domain', () => {
  const context = {
    user: { id: 'admin-id' },
  } as AuthContext;

  const user = {
    id: 'user-id',
    user_email: 'test@test.com',
  } as AuthUser;

  beforeEach(() => {
    vi.clearAllMocks();
    (internalLoadById as any).mockResolvedValue(user);
    (isUserHasCapability as any).mockReturnValue(true);
  });

  describe('addUserToken', () => {
    it('should generate token, patch user and log audit action', async () => {
      const input = {
        name: 'Test Token',
        duration: TokenDuration.Days_30,
      };

      const result = await addUserToken(context, user, input);

      // Verify result structure
      expect(result).toHaveProperty('token_id');
      expect(result).toHaveProperty('plaintext_token');
      expect(result).toHaveProperty('masked_token');
      expect(result).toHaveProperty('expires_at');
      expect(result.expires_at).not.toBeNull();

      // Verify updateAttribute call
      expect(updateAttribute).toHaveBeenCalledWith(
        context,
        user,
        user.id,
        ENTITY_TYPE_USER,
        expect.arrayContaining([
          expect.objectContaining({
            key: 'api_tokens',
            value: expect.arrayContaining([
              expect.objectContaining({
                name: 'Test Token',
                masked_token: result.masked_token,
              }),
            ]),
            operation: 'add',
          }),
        ]),
      );

      // Verify audit log
      expect(publishUserAction).toHaveBeenCalledWith({
        user,
        event_type: 'mutation',
        event_scope: 'update',
        event_access: 'administration',
        message: expect.stringContaining('generated a new API token \'Test Token\''),
        context_data: {
          id: user.id,
          entity_type: ENTITY_TYPE_USER,
          input: expect.objectContaining({
            name: 'Test Token',
            token_id: result.token_id,
          }),
        },
      });

      // Verify notify call
      expect(notify).toHaveBeenCalled();
    });

    it('should handle infinite duration', async () => {
      const input = {
        name: 'Permanent Token',
        duration: TokenDuration.Unlimited,
      };

      const result = await addUserToken(context, user, input);

      expect(result.expires_at).toBeNull();
      expect(publishUserAction).toHaveBeenCalled();
      expect(publishUserAction).toHaveBeenCalled();
    });
  });

  describe('revokeUserToken', () => {
    it('should revoke existing token', async () => {
      const userWithToken = {
        ...user,
        api_tokens: [{
          id: 'token-id',
          name: 'Test Token',
          hash: 'hash',
          created_at: 'date',
          expires_at: null,
          masked_token: '****',
        }],
      } as unknown as AuthUser;

      (internalLoadById as any).mockResolvedValue(userWithToken);

      await revokeUserToken(context, userWithToken, 'token-id');

      expect(updateAttribute).toHaveBeenCalledWith(
        context,
        userWithToken,
        user.id,
        ENTITY_TYPE_USER,
        expect.arrayContaining([
          expect.objectContaining({
            key: 'api_tokens',
            value: expect.arrayContaining([expect.objectContaining({ id: 'token-id' })]),
            operation: 'remove',
          }),
        ]),
      );
      expect(publishUserAction).toHaveBeenCalled();
    });

    it('should throw if token not found', async () => {
      await expect(revokeUserToken(context, user, 'non-existent')).rejects.toThrow('Token not found');
      await expect(revokeUserToken(context, user, 'non-existent')).rejects.toThrow('Token not found');
    });
  });
});
