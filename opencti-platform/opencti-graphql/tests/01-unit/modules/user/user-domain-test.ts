import { describe, it, expect, vi, beforeEach } from 'vitest';
import { addUserToken } from '../../../../src/modules/user/user-domain';
import { patchAttribute } from '../../../../src/database/middleware';
import { publishUserAction } from '../../../../src/listener/UserActionListener';
import { ENTITY_TYPE_USER } from '../../../../src/schema/internalObject';
import { TokenDuration } from '../../../../src/generated/graphql';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware');
vi.mock('../../../../src/listener/UserActionListener');

describe('User Domain', () => {
  const context = {
    user: { id: 'admin-id' }
  } as AuthContext;

  const user = {
    id: 'user-id',
    user_email: 'test@test.com',
  } as AuthUser;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('addUserToken', () => {
    it('should generate token, patch user and log audit action', async () => {
      const input = {
        description: 'Test Token',
        duration: TokenDuration.Days_30
      };

      const result = await addUserToken(context, user, input);

      // Verify result structure
      expect(result).toHaveProperty('token_id');
      expect(result).toHaveProperty('plaintext_token');
      expect(result).toHaveProperty('masked_token');
      expect(result).toHaveProperty('expires_at');
      expect(result.expires_at).not.toBeNull();

      // Verify patchAttribute call
      expect(patchAttribute).toHaveBeenCalledWith(
        context,
        user,
        user.id,
        ENTITY_TYPE_USER,
        expect.objectContaining({
          api_tokens: expect.arrayContaining([
            expect.objectContaining({
              name: 'Test Token',
              masked_token: result.masked_token,
            })
          ])
        }),
        { operation: 'add' }
      );

      // Verify audit log
      expect(publishUserAction).toHaveBeenCalledWith({
        user,
        event_type: 'mutation',
        event_scope: 'update',
        event_access: 'administration',
        message: expect.stringContaining(`generated a new API token 'Test Token'`),
        context_data: {
          id: user.id,
          entity_type: ENTITY_TYPE_USER,
          input: expect.objectContaining({
            description: 'Test Token',
            token_id: result.token_id,
          })
        }
      });
    });

    it('should handle infinite duration', async () => {
      const input = {
        description: 'Permanent Token',
        duration: TokenDuration.Unlimited
      };

      const result = await addUserToken(context, user, input);

      expect(result.expires_at).toBeNull();
      expect(patchAttribute).toHaveBeenCalled();
      expect(publishUserAction).toHaveBeenCalled();
    });
  });
});
