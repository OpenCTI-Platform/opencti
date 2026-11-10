import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { isSessionPresenceSupported, registerSessionPresence, unregisterSessionPresence } from '../../../../src/modules/session/session-presence-domain';
import { onSessionPresenceClose, onSessionPresenceConnect } from '../../../../src/modules/session/session-presence-ws';
import * as cache from '../../../../src/database/cache';
import * as session from '../../../../src/database/session';
import * as listener from '../../../../src/listener/UserActionListener';
import * as redis from '../../../../src/database/redis';
import * as userDomain from '../../../../src/modules/user/user-domain';
import { getStoppingState } from '../../../../src/config/conf';
import '../../../../src/modules/attributes/internalObject-registrationAttributes';
import { schemaAttributesDefinition } from '../../../../src/schema/schema-attributes';
import { ENTITY_TYPE_ACTIVITY } from '../../../../src/schema/internalObject';
import type { ObjectAttribute } from '../../../../src/schema/attribute-definition';

const GRACE_PERIOD = vi.hoisted(() => 30000);

vi.mock('../../../../src/database/cache', () => ({
  getEntityFromCache: vi.fn(),
}));

vi.mock('../../../../src/database/session', () => ({
  findSessionByRawId: vi.fn(),
  killSessionByRawId: vi.fn(),
  getSessionMiddleware: vi.fn(),
}));

vi.mock('../../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn(),
}));

vi.mock('../../../../src/database/redis', () => ({
  getClusterInstances: vi.fn(),
}));

vi.mock('../../../../src/modules/user/user-domain', () => ({
  userWithOrigin: vi.fn((req, user) => ({ ...user, origin: { socket: 'query', ip: req.ip, user_id: user.id } })),
}));

vi.mock('../../../../src/config/conf', async (importOriginal: any) => {
  const actual = await importOriginal();
  return {
    ...actual,
    default: {
      ...actual.default,
      get: vi.fn((key) => {
        if (key === 'app:session_presence:grace_period') return GRACE_PERIOD;
        return actual.default.get(key);
      }),
    },
    getStoppingState: vi.fn(() => false),
    logApp: { ...actual.logApp, error: vi.fn(), warn: vi.fn() },
  };
});

vi.mock('../../../../src/utils/access', async (importOriginal: any) => ({
  ...(await importOriginal()),
  executionContext: vi.fn().mockReturnValue('mock-context'),
  SYSTEM_USER: { id: 'system-user' },
}));

const USER = { id: 'user-id', groups: [{ internal_id: 'group-id' }], organizations: [] };
const ORIGIN = { socket: 'query', user_id: USER.id };

// Presence state is module wide: every test works on its own session id
let sessionCounter = 0;
const nextSessionId = () => {
  sessionCounter += 1;
  return `session-${sessionCounter}`;
};

const enablePresence = (enabled: boolean) => {
  vi.mocked(cache.getEntityFromCache).mockResolvedValue({ platform_session_presence_enabled: enabled } as any);
};

const storeSession = (sessionData: unknown) => {
  vi.mocked(session.findSessionByRawId).mockResolvedValue(sessionData);
};

// Nodes listed in the cluster, by their `api_enabled` flag (undefined for a node of a previous version)
const listClusterNodes = (...apiEnabledFlags: (boolean | undefined)[]) => {
  const nodes = apiEnabledFlags.map((apiEnabled, i) => ({ platform_id: `node-${i}`, api_enabled: apiEnabled, managers: [] }));
  vi.mocked(redis.getClusterInstances).mockResolvedValue(nodes as any);
};

const runPlatformNodes = (count: number) => {
  listClusterNodes(...Array.from({ length: count }, () => true));
};

describe('session presence', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
    vi.mocked(getStoppingState).mockReturnValue(false);
    enablePresence(true);
    storeSession({ user: USER });
    runPlatformNodes(1);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should logout the session after the grace period once its last connection is closed', async () => {
    const sessionId = nextSessionId();
    const connectionId = registerSessionPresence(sessionId, ORIGIN);
    unregisterSessionPresence(sessionId, connectionId);

    await vi.advanceTimersByTimeAsync(GRACE_PERIOD - 1);
    expect(session.killSessionByRawId).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    expect(session.findSessionByRawId).toHaveBeenCalledWith(sessionId);
    expect(session.killSessionByRawId).toHaveBeenCalledExactlyOnceWith(sessionId);
    expect(listener.publishUserAction).toHaveBeenCalledExactlyOnceWith({
      user: { ...USER, origin: ORIGIN },
      event_type: 'authentication',
      event_access: 'administration',
      event_scope: 'logout',
      context_data: { reason: 'last_tab_closed' },
    });
  });

  it('should keep the session while another connection is alive', async () => {
    const sessionId = nextSessionId();
    const firstConnectionId = registerSessionPresence(sessionId, ORIGIN);
    registerSessionPresence(sessionId, ORIGIN);
    unregisterSessionPresence(sessionId, firstConnectionId);

    await vi.advanceTimersByTimeAsync(GRACE_PERIOD * 2);
    expect(session.killSessionByRawId).not.toHaveBeenCalled();
  });

  it('should cancel the logout when a connection reopens within the grace period', async () => {
    const sessionId = nextSessionId();
    const connectionId = registerSessionPresence(sessionId, ORIGIN);
    unregisterSessionPresence(sessionId, connectionId);
    await vi.advanceTimersByTimeAsync(GRACE_PERIOD / 2);
    registerSessionPresence(sessionId, ORIGIN);

    await vi.advanceTimersByTimeAsync(GRACE_PERIOD * 2);
    expect(session.killSessionByRawId).not.toHaveBeenCalled();
  });

  it('should only logout the session that lost its connections', async () => {
    const closedSessionId = nextSessionId();
    const openSessionId = nextSessionId();
    const connectionId = registerSessionPresence(closedSessionId, ORIGIN);
    registerSessionPresence(openSessionId, ORIGIN);
    unregisterSessionPresence(closedSessionId, connectionId);

    await vi.advanceTimersByTimeAsync(GRACE_PERIOD);
    expect(session.killSessionByRawId).toHaveBeenCalledExactlyOnceWith(closedSessionId);
  });

  it('should ignore an unknown or already closed connection', async () => {
    const sessionId = nextSessionId();
    const connectionId = registerSessionPresence(sessionId, ORIGIN);
    registerSessionPresence(sessionId, ORIGIN);
    unregisterSessionPresence(sessionId, connectionId);
    unregisterSessionPresence(sessionId, connectionId);
    unregisterSessionPresence(nextSessionId(), 'unknown-connection');

    await vi.advanceTimersByTimeAsync(GRACE_PERIOD * 2);
    expect(session.killSessionByRawId).not.toHaveBeenCalled();
  });

  it('should not logout when the feature is disabled during the grace period', async () => {
    const sessionId = nextSessionId();
    const connectionId = registerSessionPresence(sessionId, ORIGIN);
    unregisterSessionPresence(sessionId, connectionId);
    enablePresence(false);

    await vi.advanceTimersByTimeAsync(GRACE_PERIOD);
    expect(session.killSessionByRawId).not.toHaveBeenCalled();
    expect(listener.publishUserAction).not.toHaveBeenCalled();
  });

  it('should not logout sessions whose sockets are closed by the platform shutdown', async () => {
    const sessionId = nextSessionId();
    const connectionId = registerSessionPresence(sessionId, ORIGIN);
    vi.mocked(getStoppingState).mockReturnValue(true);
    unregisterSessionPresence(sessionId, connectionId);
    vi.mocked(getStoppingState).mockReturnValue(false);

    // Even if the platform finally keeps running, nothing was scheduled
    await vi.advanceTimersByTimeAsync(GRACE_PERIOD * 2);
    expect(session.killSessionByRawId).not.toHaveBeenCalled();
  });

  it('should not logout when the platform is stopping at the end of the grace period', async () => {
    const sessionId = nextSessionId();
    const connectionId = registerSessionPresence(sessionId, ORIGIN);
    unregisterSessionPresence(sessionId, connectionId);
    vi.mocked(getStoppingState).mockReturnValue(true);

    await vi.advanceTimersByTimeAsync(GRACE_PERIOD);
    expect(session.killSessionByRawId).not.toHaveBeenCalled();
    expect(listener.publishUserAction).not.toHaveBeenCalled();
  });

  it('should still logout when the other nodes only run managers', async () => {
    listClusterNodes(true, false);
    const sessionId = nextSessionId();
    const connectionId = registerSessionPresence(sessionId, ORIGIN);
    unregisterSessionPresence(sessionId, connectionId);

    await vi.advanceTimersByTimeAsync(GRACE_PERIOD);
    expect(session.killSessionByRawId).toHaveBeenCalledExactlyOnceWith(sessionId);
  });

  it('should only be supported while at most one node serves the API', async () => {
    listClusterNodes(true);
    expect(await isSessionPresenceSupported()).toBe(true);
    listClusterNodes(true, false, false);
    expect(await isSessionPresenceSupported()).toBe(true);
    listClusterNodes(true, true);
    expect(await isSessionPresenceSupported()).toBe(false);
    // A node of a previous version doesn't tell whether it serves the API: it is counted
    listClusterNodes(true, undefined);
    expect(await isSessionPresenceSupported()).toBe(false);
  });

  it('should not logout while several platform nodes are running', async () => {
    runPlatformNodes(2);
    const sessionId = nextSessionId();
    const connectionId = registerSessionPresence(sessionId, ORIGIN);
    unregisterSessionPresence(sessionId, connectionId);

    await vi.advanceTimersByTimeAsync(GRACE_PERIOD);
    expect(session.killSessionByRawId).not.toHaveBeenCalled();
    expect(listener.publishUserAction).not.toHaveBeenCalled();
  });

  it('should only publish context data fields that the activity index maps', async () => {
    // The mapping of the context data is strict: an unknown field makes the indexing of the event fail
    const sessionId = nextSessionId();
    const connectionId = registerSessionPresence(sessionId, ORIGIN);
    unregisterSessionPresence(sessionId, connectionId);

    await vi.advanceTimersByTimeAsync(GRACE_PERIOD);
    const contextData = vi.mocked(listener.publishUserAction).mock.calls[0][0].context_data as object;
    const contextDataAttribute = schemaAttributesDefinition.getAttribute(ENTITY_TYPE_ACTIVITY, 'context_data') as ObjectAttribute;
    const mappedFields = contextDataAttribute.mappings.map(({ name }) => name);
    expect(Object.keys(contextData)).toEqual(['reason']);
    Object.keys(contextData).forEach((field) => expect(mappedFields).toContain(field));
  });

  it('should wait for the new grace period when a tab comes back and closes again during the checks', async () => {
    let resolveSession: (value: unknown) => void = () => {};
    vi.mocked(session.findSessionByRawId).mockReturnValueOnce(new Promise((resolve) => {
      resolveSession = resolve;
    }));
    const sessionId = nextSessionId();
    const firstConnectionId = registerSessionPresence(sessionId, ORIGIN);
    unregisterSessionPresence(sessionId, firstConnectionId);
    // The first grace period ends: its logout now waits for the session store
    await vi.advanceTimersByTimeAsync(GRACE_PERIOD);
    expect(session.findSessionByRawId).toHaveBeenCalledOnce();

    // Meanwhile a tab reconnects and closes again, starting a new grace period
    const secondConnectionId = registerSessionPresence(sessionId, ORIGIN);
    unregisterSessionPresence(sessionId, secondConnectionId);
    resolveSession({ user: USER });
    await vi.advanceTimersByTimeAsync(GRACE_PERIOD - 1);
    expect(session.killSessionByRawId).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    expect(session.killSessionByRawId).toHaveBeenCalledExactlyOnceWith(sessionId);
  });

  it('should not publish a logout for a session already logged out or expired', async () => {
    storeSession(null);
    const sessionId = nextSessionId();
    const connectionId = registerSessionPresence(sessionId, ORIGIN);
    unregisterSessionPresence(sessionId, connectionId);

    await vi.advanceTimersByTimeAsync(GRACE_PERIOD);
    expect(session.killSessionByRawId).not.toHaveBeenCalled();
    expect(listener.publishUserAction).not.toHaveBeenCalled();
  });

  describe('graphql-ws hooks', () => {
    const OPEN = 1;
    const CLOSED = 3;

    const mockSessionMiddleware = (sessionId: string, sessionData: unknown) => {
      const middleware = (req: any, _res: unknown, next: () => void) => {
        req.sessionID = sessionId;
        req.session = sessionData;
        next();
      };
      vi.mocked(session.getSessionMiddleware).mockResolvedValue(middleware as any);
    };

    const buildContext = (readyState = OPEN) => {
      const socket = { readyState, OPEN };
      const request = { ip: '10.0.0.1' };
      return { extra: { socket, request } } as any;
    };

    it('should track an authenticated socket until it closes, with the origin of an explicit logout', async () => {
      const sessionId = nextSessionId();
      mockSessionMiddleware(sessionId, { user: USER });
      const ctx = buildContext();

      await onSessionPresenceConnect(ctx);
      onSessionPresenceClose(ctx);
      await vi.advanceTimersByTimeAsync(GRACE_PERIOD);

      expect(session.killSessionByRawId).toHaveBeenCalledExactlyOnceWith(sessionId);
      expect(userDomain.userWithOrigin).toHaveBeenCalledWith(ctx.extra.request, USER);
      const { user } = vi.mocked(listener.publishUserAction).mock.calls[0][0];
      expect(user.origin).toEqual({ socket: 'query', ip: '10.0.0.1', user_id: USER.id });
    });

    it('should logout a tab opened before the feature was enabled', async () => {
      enablePresence(false);
      const sessionId = nextSessionId();
      mockSessionMiddleware(sessionId, { user: USER });
      const ctx = buildContext();

      await onSessionPresenceConnect(ctx);
      enablePresence(true);
      onSessionPresenceClose(ctx);
      await vi.advanceTimersByTimeAsync(GRACE_PERIOD);

      expect(session.killSessionByRawId).toHaveBeenCalledExactlyOnceWith(sessionId);
    });

    it('should not logout a tracked tab while the feature is disabled', async () => {
      enablePresence(false);
      mockSessionMiddleware(nextSessionId(), { user: USER });
      const ctx = buildContext();

      await onSessionPresenceConnect(ctx);
      onSessionPresenceClose(ctx);
      await vi.advanceTimersByTimeAsync(GRACE_PERIOD);

      expect(session.killSessionByRawId).not.toHaveBeenCalled();
    });

    it('should not track an unauthenticated socket', async () => {
      mockSessionMiddleware(nextSessionId(), {});
      const ctx = buildContext();

      await onSessionPresenceConnect(ctx);
      onSessionPresenceClose(ctx);
      await vi.advanceTimersByTimeAsync(GRACE_PERIOD);

      expect(session.killSessionByRawId).not.toHaveBeenCalled();
    });

    it('should not track a socket closed while its session was parsed', async () => {
      mockSessionMiddleware(nextSessionId(), { user: USER });
      const ctx = buildContext(CLOSED);

      await onSessionPresenceConnect(ctx);
      onSessionPresenceClose(ctx);
      await vi.advanceTimersByTimeAsync(GRACE_PERIOD);

      expect(session.killSessionByRawId).not.toHaveBeenCalled();
    });

    it('should accept the socket even if the presence fails', async () => {
      vi.mocked(session.getSessionMiddleware).mockRejectedValue(new Error('store unavailable'));

      await expect(onSessionPresenceConnect(buildContext())).resolves.toBeUndefined();
    });
  });
});
