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

const USER = { id: 'user-1', internal_id: 'user-1', name: 'User 1', user_email: 'user1@opencti.io', groups: [], organizations: [] };

// A request authenticated by a session opened at the given login time
const sessionRequest = (loginTime: number) => {
  const req = {
    ip: '127.0.0.1',
    headers: {},
    header: () => undefined,
    sessionID: 'session-id',
    session: {
      user: { id: USER.id, session_creation: new Date(loginTime).toISOString() },
      destroy: vi.fn((callback: (err?: unknown) => void) => {
        // As express-session does, the session is removed from the request
        delete (req as { session?: unknown }).session;
        callback();
      }),
    },
  };
  return req;
};

describe('authenticateUserFromRequest: maximum lifetime of a session', () => {
  const context = executionContext('test');

  beforeEach(() => {
    vi.mocked(publishUserAction).mockClear();
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(new Map([[USER.id, USER]]) as any);
  });

  afterAll(() => {
    delete process.env.APP__SESSION_MAX_LIFETIME;
  });

  it('should authenticate the user of a session under its maximum lifetime', async () => {
    const req = sessionRequest(Date.now() - TWELVE_HOURS + 60 * 1000);
    const { destroy } = req.session;
    const user = await authenticateUserFromRequest(context, req as any);
    expect(user?.id).toEqual(USER.id);
    expect(destroy).not.toHaveBeenCalled();
    expect(publishUserAction).not.toHaveBeenCalled();
  });

  it('should end a session over its maximum lifetime, even when its user is active', async () => {
    const req = sessionRequest(Date.now() - TWELVE_HOURS - 60 * 1000);
    const { destroy } = req.session;
    const user = await authenticateUserFromRequest(context, req as any);
    expect(user).toBeUndefined();
    expect(destroy).toHaveBeenCalledTimes(1);
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
    const req = sessionRequest(Date.now() - TWELVE_HOURS - 60 * 1000);
    await authenticateUserFromRequest(context, req as any);
    expect(await authenticateUserFromRequest(context, req as any)).toBeUndefined();
    // The logout is recorded once
    expect(publishUserAction).toHaveBeenCalledTimes(1);
  });
});
