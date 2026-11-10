import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as Cache from '../../../../src/database/cache';
import { logApp } from '../../../../src/config/conf';
import { authenticateUserFromRequest } from '../../../../src/modules/user/user-domain';
import { ENTITY_TYPE_USER } from '../../../../src/schema/internalObject';
import { SYSTEM_USER } from '../../../../src/utils/access';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/database/cache');
vi.mock('../../../../src/database/redis'); // to prevent connection attempts
vi.mock('../../../../src/config/conf', async () => {
  const actual = await vi.importActual('../../../../src/config/conf');
  return {
    ...actual,
    logApp: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
  };
});

const context = { user: SYSTEM_USER, req: {} } as unknown as AuthContext;

const cachedUser = {
  id: 'cached-user-id',
  internal_id: 'cached-user-id',
  name: 'Cached User',
  user_email: 'cached.user@example.com',
  capabilities: [{ name: 'KNOWLEDGE' }],
} as unknown as AuthUser;

const buildSessionRequest = (sessionUserId: string) => {
  const destroy = vi.fn((callback: (err?: unknown) => void) => callback());
  const req = {
    headers: {},
    header: (_: string) => undefined,
    ip: '127.0.0.1',
    session: {
      user: { id: sessionUserId, session_creation: '2026-01-01T00:00:00.000Z', otp_validated: true, password_valid_until: null },
      destroy,
    },
  };
  return { req, destroy };
};

describe('authenticateUserFromRequest - session', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.spyOn(Cache, 'getEntitiesMapFromCache').mockImplementation(async (_ctx, _user, type) => {
      if (type === ENTITY_TYPE_USER) {
        return new Map([[cachedUser.id, cachedUser]]) as any;
      }
      return new Map() as any;
    });
  });

  it('authenticates the cached user bound to the session', async () => {
    const { req, destroy } = buildSessionRequest(cachedUser.id);
    const user = await authenticateUserFromRequest(context, req);
    expect(user?.id).toBe(cachedUser.id);
    expect(user?.name).toBe('Cached User');
    expect(user?.capabilities).toEqual([{ name: 'KNOWLEDGE' }]);
    // Session fields are still exposed to the request
    expect((user as unknown as { otp_validated: boolean }).otp_validated).toBe(true);
    expect(destroy).not.toHaveBeenCalled();
    expect(logApp.warn).not.toHaveBeenCalled();
  });

  it('treats a session whose user is missing from the cache as unauthenticated', async () => {
    const { req, destroy } = buildSessionRequest('unknown-user-id');
    const user = await authenticateUserFromRequest(context, req);
    expect(user).toBeUndefined();
    expect(destroy).toHaveBeenCalledTimes(1);
    expect(logApp.warn).toHaveBeenCalledWith(
      '[AUTH] Session user missing from the users cache, session destroyed',
      { user_id: 'unknown-user-id' },
    );
  });

  it('stays unauthenticated when the session cannot be destroyed', async () => {
    const { req, destroy } = buildSessionRequest('unknown-user-id');
    const destroyError = new Error('store unavailable');
    destroy.mockImplementation((callback: (err?: unknown) => void) => callback(destroyError));
    const user = await authenticateUserFromRequest(context, req);
    expect(user).toBeUndefined();
    expect(logApp.warn).toHaveBeenCalledWith('[AUTH] Fail to destroy the session', { cause: destroyError });
  });
});
