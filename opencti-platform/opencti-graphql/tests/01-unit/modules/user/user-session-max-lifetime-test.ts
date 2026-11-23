import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';

const TWELVE_HOURS = 12 * 60 * 60 * 1000;
// The maximum lifetime is read from the configuration, which is loaded with the first import
vi.hoisted(() => {
  process.env.APP__SESSION_MAX_LIFETIME = String(12 * 60 * 60 * 1000);
});

vi.mock('../../../../src/database/middleware', () => ({
  createEntity: vi.fn(),
  createRelation: vi.fn().mockResolvedValue({}),
  patchAttribute: vi.fn().mockResolvedValue({ element: {} }),
  updateAttribute: vi.fn().mockResolvedValue({ element: {} }),
  deleteRelationsByFromAndTo: vi.fn().mockResolvedValue({}),
}));

vi.mock('../../../../src/database/engine', () => ({
  elLoadBy: vi.fn().mockResolvedValue(null),
  elRawDeleteByQuery: vi.fn().mockResolvedValue({}),
}));

vi.mock('../../../../src/database/cache', () => ({
  getEntitiesMapFromCache: vi.fn(),
  getEntityFromCache: vi.fn().mockResolvedValue({ platform_organization: null, platform_session_max_concurrent: 0 }),
  getEntitiesListFromCache: vi.fn().mockResolvedValue([]),
}));

vi.mock('../../../../src/database/redis', () => ({
  notify: vi.fn().mockResolvedValue({}),
  redisClearLocalAuthLockout: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn().mockResolvedValue({}),
}));

vi.mock('../../../../src/domain/group', () => ({
  findGroupPaginated: vi.fn().mockResolvedValue({ edges: [] }),
  defaultMarkingDefinitionsFromGroups: vi.fn().mockResolvedValue([]),
}));

// The session store is simulated: deleting a session tells, as the real stores do, whether this call deleted it
const liveSessions = vi.hoisted(() => new Set<string>());
vi.mock('../../../../src/database/session', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/session')>()),
  endSessionByRawId: vi.fn(async (sessionId: string) => liveSessions.delete(sessionId)),
}));

vi.mock('passport', () => ({
  default: {
    authenticate: vi.fn(),
    _strategy: vi.fn().mockReturnValue({ logger: null }),
  },
}));

vi.mock('../../../../src/modules/authenticationProvider/providers-configuration', () => ({
  PROVIDERS: [],
  LOCAL_STRATEGY_IDENTIFIER: 'local',
  isLocalAuthForcedEnabledFromEnv: vi.fn().mockReturnValue(true),
  getConfigurationAdminEmail: vi.fn(),
  getConfigurationAdminPassword: vi.fn(),
  getConfigurationAdminToken: vi.fn(),
}));

vi.mock('../../../../src/domain/settings', () => ({
  getSettings: vi.fn().mockResolvedValue({ local_auth: { enabled: true }, platform_organization: null, platform_session_max_concurrent: 0 }),
}));

import { authenticateUserFromRequest } from '../../../../src/modules/user/user-domain';
import { getEntitiesMapFromCache } from '../../../../src/database/cache';
import { publishUserAction } from '../../../../src/listener/UserActionListener';
import { executionContext } from '../../../../src/utils/access';
import { endSessionByRawId } from '../../../../src/database/session';

const USER = { id: 'user-1', internal_id: 'user-1', name: 'User 1', user_email: 'user1@opencti.io', groups: [], organizations: [] };

// A request authenticated by a session opened at the given login time.
// Each request holds its own copy of the session, as each one reads it from the store.
const SESSION_ID = 'session-id';
const sessionRequest = (loginTime: number) => ({
  ip: '127.0.0.1',
  headers: {},
  header: () => undefined,
  sessionID: SESSION_ID,
  session: { user: { id: USER.id, session_creation: new Date(loginTime).toISOString() } } as { user: { id: string; session_creation: string } } | undefined,
});

describe('authenticateUserFromRequest: maximum lifetime of a session', () => {
  const context = executionContext('test');
  const overLimitLoginTime = () => Date.now() - TWELVE_HOURS - 60 * 1000;

  beforeEach(() => {
    liveSessions.clear();
    liveSessions.add(SESSION_ID);
    vi.mocked(publishUserAction).mockClear();
    vi.mocked(endSessionByRawId).mockClear();
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(new Map([[USER.id, USER]]) as any);
  });

  afterAll(() => {
    delete process.env.APP__SESSION_MAX_LIFETIME;
  });

  it('should authenticate the user of a session under its maximum lifetime', async () => {
    const req = sessionRequest(Date.now() - TWELVE_HOURS + 60 * 1000);
    const user = await authenticateUserFromRequest(context, req as any);
    expect(user?.id).toEqual(USER.id);
    expect(endSessionByRawId).not.toHaveBeenCalled();
    expect(publishUserAction).not.toHaveBeenCalled();
  });

  it('should end a session over its maximum lifetime, even when its user is active', async () => {
    const req = sessionRequest(overLimitLoginTime());
    const user = await authenticateUserFromRequest(context, req as any);
    expect(user).toBeUndefined();
    expect(endSessionByRawId).toHaveBeenCalledWith(SESSION_ID);
    expect(liveSessions.has(SESSION_ID)).toBe(false);
    // Removed from the request, so that the end of the request does not save it again
    expect(req.session).toBeUndefined();
    expect(publishUserAction).toHaveBeenCalledTimes(1);
    expect(publishUserAction).toHaveBeenCalledWith(expect.objectContaining({
      user: expect.objectContaining({ id: USER.id, origin: expect.objectContaining({ user_id: USER.id }) }),
      event_type: 'authentication',
      event_scope: 'logout',
      context_data: { reason: 'max_lifetime' },
    }));
  });

  it('should not authenticate the next requests of an ended session', async () => {
    const req = sessionRequest(overLimitLoginTime());
    await authenticateUserFromRequest(context, req as any);
    expect(await authenticateUserFromRequest(context, req as any)).toBeUndefined();
    expect(publishUserAction).toHaveBeenCalledTimes(1);
  });

  it('should record the logout once when parallel requests of the session reach its maximum lifetime', async () => {
    const loginTime = overLimitLoginTime();
    const requests = [sessionRequest(loginTime), sessionRequest(loginTime), sessionRequest(loginTime)];

    const users = await Promise.all(requests.map((req) => authenticateUserFromRequest(context, req as any)));

    expect(users).toEqual([undefined, undefined, undefined]);
    expect(endSessionByRawId).toHaveBeenCalledTimes(3);
    expect(publishUserAction).toHaveBeenCalledTimes(1);
  });

  it('should not authenticate the request when the session cannot be deleted', async () => {
    vi.mocked(endSessionByRawId).mockRejectedValueOnce(new Error('Redis unavailable'));
    const req = sessionRequest(overLimitLoginTime());
    expect(await authenticateUserFromRequest(context, req as any)).toBeUndefined();
    expect(publishUserAction).not.toHaveBeenCalled();
  });
});
