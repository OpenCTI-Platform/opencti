import { IncomingMessage, ServerResponse } from 'node:http';
import { Socket } from 'node:net';
import { promisify } from 'node:util';
import session from 'express-session';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as Cache from '../../../../src/database/cache';
import * as MiddlewareLoader from '../../../../src/database/middleware-loader';
import { logApp } from '../../../../src/config/conf';
import { authenticateUserFromRequest } from '../../../../src/modules/user/user-domain';
import { ENTITY_TYPE_USER } from '../../../../src/schema/internalObject';
import { SYSTEM_USER } from '../../../../src/utils/access';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/database/cache');
vi.mock('../../../../src/database/redis'); // to prevent connection attempts
vi.mock('../../../../src/database/middleware-loader', async () => {
  const actual = await vi.importActual('../../../../src/database/middleware-loader');
  return { ...actual, internalLoadById: vi.fn() };
});
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

// A user that exists in the database but has not reached the users cache of this node yet
const lateUser = {
  id: 'late-user-id',
  internal_id: 'late-user-id',
  name: 'Late User',
  user_email: 'late.user@example.com',
  capabilities: [{ name: 'KNOWLEDGE' }],
} as unknown as AuthUser;
const lateStoredUser = { id: lateUser.id, internal_id: lateUser.internal_id, entity_type: ENTITY_TYPE_USER, name: 'Late User' };

let cacheUsers: Map<string, AuthUser>;

const buildSessionRequest = (sessionUserId: string) => {
  const regenerate = vi.fn((callback: (err?: unknown) => void) => callback());
  const req = {
    headers: {},
    header: (_: string) => undefined,
    ip: '127.0.0.1',
    session: {
      user: { id: sessionUserId, session_creation: '2026-01-01T00:00:00.000Z', otp_validated: true, password_valid_until: null },
      regenerate,
    },
  };
  return { req, regenerate };
};

describe('authenticateUserFromRequest - session', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    cacheUsers = new Map([[cachedUser.id, cachedUser]]);
    vi.spyOn(Cache, 'getEntitiesMapFromCache').mockImplementation(async (_ctx, _user, type) => {
      if (type === ENTITY_TYPE_USER) {
        return new Map(cacheUsers) as any;
      }
      return new Map() as any;
    });
    // Like the users cache add handler: the complete user is built from the database
    vi.spyOn(Cache, 'addCacheForEntity').mockImplementation(async (instance) => {
      const { internal_id } = instance as { internal_id: string };
      if (internal_id === lateUser.internal_id) {
        cacheUsers.set(lateUser.id, lateUser);
      }
    });
    vi.spyOn(MiddlewareLoader, 'internalLoadById').mockImplementation(async (_ctx, _user, id) => {
      return (id === lateUser.id ? lateStoredUser : undefined) as any;
    });
  });

  it('authenticates the cached user bound to the session', async () => {
    const { req, regenerate } = buildSessionRequest(cachedUser.id);
    const user = await authenticateUserFromRequest(context, req);
    expect(user?.id).toBe(cachedUser.id);
    expect(user?.name).toBe('Cached User');
    expect(user?.capabilities).toEqual([{ name: 'KNOWLEDGE' }]);
    // Session fields are still exposed to the request
    expect((user as unknown as { otp_validated: boolean }).otp_validated).toBe(true);
    expect(MiddlewareLoader.internalLoadById).not.toHaveBeenCalled();
    expect(regenerate).not.toHaveBeenCalled();
    expect(logApp.warn).not.toHaveBeenCalled();
  });

  it('adds to the cache a session user that exists but is missing from the cache, and authenticates it', async () => {
    const { req, regenerate } = buildSessionRequest(lateUser.id);
    const user = await authenticateUserFromRequest(context, req);
    expect(Cache.addCacheForEntity).toHaveBeenCalledWith(lateStoredUser);
    expect(user?.id).toBe(lateUser.id);
    expect(user?.name).toBe('Late User');
    expect(user?.capabilities).toEqual([{ name: 'KNOWLEDGE' }]);
    expect((user as unknown as { otp_validated: boolean }).otp_validated).toBe(true);
    expect(regenerate).not.toHaveBeenCalled();
    expect(logApp.warn).toHaveBeenCalledWith('[AUTH] Session user missing from the users cache, adding it', { user_id: lateUser.id });
  });

  it('keeps the session of an existing user that cannot be added to the cache, without authenticating it', async () => {
    vi.mocked(Cache.addCacheForEntity).mockResolvedValue(undefined);
    const { req, regenerate } = buildSessionRequest(lateUser.id);
    const user = await authenticateUserFromRequest(context, req);
    expect(user).toBeUndefined();
    expect(regenerate).not.toHaveBeenCalled();
    expect(logApp.warn).toHaveBeenCalledWith('[AUTH] Session user cannot be added to the users cache', { user_id: lateUser.id });
  });

  it('replaces the session of a user that no longer exists and treats the request as unauthenticated', async () => {
    const { req, regenerate } = buildSessionRequest('unknown-user-id');
    const user = await authenticateUserFromRequest(context, req);
    expect(user).toBeUndefined();
    expect(MiddlewareLoader.internalLoadById).toHaveBeenCalledWith(context, SYSTEM_USER, 'unknown-user-id', { type: ENTITY_TYPE_USER });
    expect(Cache.addCacheForEntity).not.toHaveBeenCalled();
    expect(regenerate).toHaveBeenCalledTimes(1);
    expect(logApp.warn).toHaveBeenCalledWith('[AUTH] Session user no longer exists, session destroyed', { user_id: 'unknown-user-id' });
  });

  it('keeps the session when the database cannot be read', async () => {
    const databaseError = new Error('database unavailable');
    vi.mocked(MiddlewareLoader.internalLoadById).mockRejectedValue(databaseError);
    const { req, regenerate } = buildSessionRequest('unknown-user-id');
    // The caller (createAuthenticatedContext) handles the failure as an unauthenticated request
    await expect(authenticateUserFromRequest(context, req)).rejects.toThrow(databaseError);
    expect(regenerate).not.toHaveBeenCalled();
  });

  it('stays unauthenticated when the session cannot be regenerated', async () => {
    const { req, regenerate } = buildSessionRequest('unknown-user-id');
    const regenerateError = new Error('store unavailable');
    regenerate.mockImplementation((callback: (err?: unknown) => void) => callback(regenerateError));
    const user = await authenticateUserFromRequest(context, req);
    expect(user).toBeUndefined();
    expect(logApp.warn).toHaveBeenCalledWith('[AUTH] Fail to regenerate the session', { cause: regenerateError });
  });
});

describe('authenticateUserFromRequest - session, with the real session middleware', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.spyOn(Cache, 'getEntitiesMapFromCache').mockResolvedValue(new Map() as any);
    vi.spyOn(MiddlewareLoader, 'internalLoadById').mockResolvedValue(undefined as any);
  });

  it('gives the request a new empty session when the session user no longer exists', async () => {
    const sessionStore = new session.MemoryStore();
    const sessionMiddleware = session({ store: sessionStore, secret: 'test-secret', resave: false, saveUninitialized: false });
    const req = new IncomingMessage(new Socket()) as any;
    req.url = '/graphql';
    req.originalUrl = '/graphql';
    const res = new ServerResponse(req);
    await promisify(sessionMiddleware)(req, res);
    // A session saved for a user that has been deleted since
    req.session.user = { id: 'deleted-user-id', session_creation: '2026-01-01T00:00:00.000Z', otp_validated: true };
    await promisify(req.session.save.bind(req.session))();
    const staleSessionId = req.sessionID;

    const user = await authenticateUserFromRequest(context, req);

    expect(user).toBeUndefined();
    // The stale session is gone from the store
    expect(await promisify(sessionStore.get.bind(sessionStore))(staleSessionId)).toBeFalsy();
    // The request still has a session, so a login in the same request (token mutation) can bind its user to it
    expect(req.sessionID).not.toBe(staleSessionId);
    expect(req.session).toBeDefined();
    expect(req.session.user).toBeUndefined();
    expect(typeof req.session.regenerate).toBe('function');
  });
});
