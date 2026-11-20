import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  isSessionPresenceManagerEnabled,
  isSessionPresenceSupported,
  logoutAbandonedSessions,
  registerSessionPresence,
  SESSION_PRESENCE_MANAGER_ID,
  unregisterSessionPresence,
} from '../../../../src/modules/session/session-presence-domain';
import { onSessionPresenceClose, onSessionPresenceConnect } from '../../../../src/modules/session/session-presence-ws';
import * as cache from '../../../../src/database/cache';
import * as session from '../../../../src/database/session';
import * as listener from '../../../../src/listener/UserActionListener';
import * as redis from '../../../../src/database/redis';
import * as userDomain from '../../../../src/modules/user/user-domain';
import { getStoppingState, isFeatureEnabled } from '../../../../src/config/conf';
import '../../../../src/modules/attributes/internalObject-registrationAttributes';
import { schemaAttributesDefinition } from '../../../../src/schema/schema-attributes';
import { ENTITY_TYPE_ACTIVITY } from '../../../../src/schema/internalObject';
import type { ObjectAttribute } from '../../../../src/schema/attribute-definition';

const { GRACE_PERIOD, LEASE_TTL, sessionManager } = vi.hoisted(() => ({ GRACE_PERIOD: 30000, LEASE_TTL: 30000, sessionManager: { value: 'shared' } }));
const RENEW_INTERVAL = LEASE_TTL / 3;

// In memory store with the semantics of the Redis scripts (tested against Redis in the integration tests),
// shared by every node of the tests: the module under test is one node, the others write to the store directly.
const store = vi.hoisted(() => {
  const leases = new Map<string, Map<string, number>>();
  const closing = new Map<string, number>();
  const origins = new Map<string, unknown>();
  const due = new Map<string, number>();
  const now = () => Date.now();
  const purgeExpiredLeases = (sessionId: string) => {
    const sessionLeases = leases.get(sessionId);
    sessionLeases?.forEach((expiry, connectionId) => {
      if (expiry <= now()) sessionLeases.delete(connectionId);
    });
    if (sessionLeases?.size === 0) leases.delete(sessionId);
  };
  return {
    reset: () => {
      leases.clear();
      closing.clear();
      origins.clear();
      due.clear();
    },
    isDue: (sessionId: string) => due.has(sessionId),
    checkTime: (sessionId: string) => due.get(sessionId),
    hasLiveLease: (sessionId: string, connectionId: string) => (leases.get(sessionId)?.get(connectionId) ?? 0) > now(),
    saveSessionLeases: vi.fn(async (sessionId: string, connectionIds: string[], leaseTtl: number, _keysTtl: number, origin?: unknown) => {
      if ((closing.get(sessionId) ?? 0) > now()) return undefined;
      const expiry = now() + leaseTtl;
      const sessionLeases = leases.get(sessionId) ?? new Map<string, number>();
      connectionIds.forEach((connectionId) => sessionLeases.set(connectionId, expiry));
      leases.set(sessionId, sessionLeases);
      if (origin) origins.set(sessionId, origin);
      return expiry;
    }),
    removeSessionLease: vi.fn(async (sessionId: string, connectionId: string) => {
      leases.get(sessionId)?.delete(connectionId);
      purgeExpiredLeases(sessionId);
      return { liveLeases: leases.get(sessionId)?.size ?? 0, now: now() };
    }),
    checkSessionLeases: vi.fn(async (sessionId: string, closingTtl: number) => {
      purgeExpiredLeases(sessionId);
      const sessionLeases = leases.get(sessionId);
      if (sessionLeases) return { isAlive: true, time: Math.max(...sessionLeases.values()) };
      if (closingTtl > 0) closing.set(sessionId, now() + closingTtl);
      return { isAlive: false, time: now() };
    }),
    scheduleSessionCheck: vi.fn(async (sessionId: string, checkTime: number, mode: 'GT' | 'LT') => {
      const current = due.get(sessionId);
      if (current === undefined || (mode === 'GT' ? checkTime > current : checkTime < current)) due.set(sessionId, checkTime);
    }),
    findDueSessions: vi.fn(async (limit: number) => {
      return [...due.entries()].filter(([, checkTime]) => checkTime <= now()).sort((a, b) => a[1] - b[1]).slice(0, limit).map(([id]) => id);
    }),
    findSessionOrigin: vi.fn(async (sessionId: string) => origins.get(sessionId)),
    releaseSessionPresence: vi.fn(async (sessionId: string) => {
      origins.delete(sessionId);
      due.delete(sessionId);
    }),
  };
});

vi.mock('../../../../src/modules/session/session-presence-store', () => store);

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
        if (key === 'app:session_presence:lease_ttl') return LEASE_TTL;
        if (key === 'app:session_manager') return sessionManager.value;
        return actual.default.get(key);
      }),
    },
    getStoppingState: vi.fn(() => false),
    isFeatureEnabled: vi.fn(() => true),
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

// The connections of this node live as long as the module: every test works on its own session id
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

// The session presence manager runs on any node, after some time
const sweepAfter = async (time: number) => {
  await vi.advanceTimersByTimeAsync(time);
  await logoutAbandonedSessions();
};

// Nodes listed in the cluster, by their `api_enabled` flag (undefined for a node of a previous version)
const listClusterNodes = (...apiEnabledFlags: (boolean | undefined)[]) => {
  const nodes = apiEnabledFlags.map((apiEnabled, i) => ({ platform_id: `node-${i}`, api_enabled: apiEnabled, managers: [] }));
  vi.mocked(redis.getClusterInstances).mockResolvedValue(nodes as any);
};

// A tab on another node: its lease is written by that node, never by the module under test
const openTabOnAnotherNode = async (sessionId: string) => {
  const expiry = await store.saveSessionLeases(sessionId, [`other-node-${sessionId}`], LEASE_TTL, 0, ORIGIN);
  await store.scheduleSessionCheck(sessionId, (expiry as number) + GRACE_PERIOD, 'GT');
};

// The other node renews the lease of its tab, until the end of the given time
const keepTabOpenOnAnotherNode = async (sessionId: string, time: number) => {
  for (let elapsed = 0; elapsed < time; elapsed += RENEW_INTERVAL) {
    await openTabOnAnotherNode(sessionId);
    await vi.advanceTimersByTimeAsync(Math.min(RENEW_INTERVAL, time - elapsed));
  }
  await openTabOnAnotherNode(sessionId);
};

describe('session presence', () => {
  // The leases renewal of the node is a timer started once for the module
  beforeAll(() => {
    vi.useFakeTimers();
  });

  afterAll(() => {
    vi.useRealTimers();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    store.reset();
    vi.mocked(getStoppingState).mockReturnValue(false);
    vi.mocked(isFeatureEnabled).mockReturnValue(true);
    enablePresence(true);
    storeSession({ user: USER });
    listClusterNodes(true);
  });

  it('should hold a lease for a connection, and schedule the check of its session', async () => {
    const sessionId = nextSessionId();
    const connectionId = await registerSessionPresence(sessionId, ORIGIN) as string;

    expect(store.hasLiveLease(sessionId, connectionId)).toBe(true);
    expect(await store.findSessionOrigin(sessionId)).toEqual(ORIGIN);
    expect(store.checkTime(sessionId)).toEqual(Date.now() + LEASE_TTL + GRACE_PERIOD);
  });

  it('should renew the lease of an open connection, and push the check of its session forward', async () => {
    const sessionId = nextSessionId();
    const connectionId = await registerSessionPresence(sessionId, ORIGIN) as string;

    await vi.advanceTimersByTimeAsync(3 * LEASE_TTL);
    expect(store.hasLiveLease(sessionId, connectionId)).toBe(true);
    expect(store.checkTime(sessionId)).toBeGreaterThan(Date.now() + GRACE_PERIOD);
  });

  it('should bring the check forward to the end of the grace period once the last connection is closed', async () => {
    const sessionId = nextSessionId();
    const firstConnectionId = await registerSessionPresence(sessionId, ORIGIN) as string;
    const secondConnectionId = await registerSessionPresence(sessionId, ORIGIN) as string;

    await unregisterSessionPresence(sessionId, firstConnectionId);
    expect(store.hasLiveLease(sessionId, firstConnectionId)).toBe(false);
    expect(store.checkTime(sessionId)).toEqual(Date.now() + LEASE_TTL + GRACE_PERIOD);

    await unregisterSessionPresence(sessionId, secondConnectionId);
    expect(store.checkTime(sessionId)).toEqual(Date.now() + GRACE_PERIOD);
  });

  it('should not write anything to Redis while the setting is off', async () => {
    enablePresence(false);
    const sessionId = nextSessionId();
    const connectionId = await registerSessionPresence(sessionId, ORIGIN) as string;
    await vi.advanceTimersByTimeAsync(2 * RENEW_INTERVAL);
    await unregisterSessionPresence(sessionId, connectionId);

    expect(store.saveSessionLeases).not.toHaveBeenCalled();
    expect(store.removeSessionLease).not.toHaveBeenCalled();
    expect(store.scheduleSessionCheck).not.toHaveBeenCalled();
  });

  it('should cover the tabs already open at the next renewal once the setting is enabled', async () => {
    enablePresence(false);
    const sessionId = nextSessionId();
    const connectionId = await registerSessionPresence(sessionId, ORIGIN) as string;
    enablePresence(true);

    await vi.advanceTimersByTimeAsync(RENEW_INTERVAL);
    expect(store.hasLiveLease(sessionId, connectionId)).toBe(true);
    await sweepAfter(3 * LEASE_TTL);
    expect(session.killSessionByRawId).not.toHaveBeenCalled();

    await unregisterSessionPresence(sessionId, connectionId);
    await sweepAfter(GRACE_PERIOD);
    expect(session.killSessionByRawId).toHaveBeenCalledExactlyOnceWith(sessionId);
    expect(vi.mocked(listener.publishUserAction).mock.calls[0][0].user.origin).toEqual(ORIGIN);
  });

  it('should keep a session when one of its tabs closes before the others got their lease', async () => {
    enablePresence(false);
    const sessionId = nextSessionId();
    const closedConnectionId = await registerSessionPresence(sessionId, ORIGIN) as string;
    await registerSessionPresence(sessionId, ORIGIN);
    enablePresence(true);
    // Closed right after the activation: the other tab gets its lease at the next renewal, within the grace period
    await unregisterSessionPresence(sessionId, closedConnectionId);

    await sweepAfter(GRACE_PERIOD);
    expect(session.killSessionByRawId).not.toHaveBeenCalled();
  });

  it('should logout the session after the grace period once its last connection is closed', async () => {
    const sessionId = nextSessionId();
    const connectionId = await registerSessionPresence(sessionId, ORIGIN) as string;
    await unregisterSessionPresence(sessionId, connectionId);

    await sweepAfter(GRACE_PERIOD - 1);
    expect(session.killSessionByRawId).not.toHaveBeenCalled();

    await sweepAfter(1);
    expect(session.killSessionByRawId).toHaveBeenCalledExactlyOnceWith(sessionId);
    expect(listener.publishUserAction).toHaveBeenCalledExactlyOnceWith({
      user: { ...USER, origin: ORIGIN },
      event_type: 'authentication',
      event_access: 'administration',
      event_scope: 'logout',
      context_data: { reason: 'last_tab_closed' },
    });
    expect(store.isDue(sessionId)).toBe(false);
  });

  it('should keep the session while another connection is alive, renewing its lease', async () => {
    const sessionId = nextSessionId();
    const firstConnectionId = await registerSessionPresence(sessionId, ORIGIN) as string;
    await registerSessionPresence(sessionId, ORIGIN);
    await unregisterSessionPresence(sessionId, firstConnectionId);

    // Well after the lease ttl: only the renewal keeps the other connection alive
    await sweepAfter(3 * LEASE_TTL);
    expect(session.killSessionByRawId).not.toHaveBeenCalled();
    expect(store.isDue(sessionId)).toBe(true);
  });

  it('should cancel the logout when a connection reopens within the grace period', async () => {
    const sessionId = nextSessionId();
    const connectionId = await registerSessionPresence(sessionId, ORIGIN) as string;
    await unregisterSessionPresence(sessionId, connectionId);
    await vi.advanceTimersByTimeAsync(GRACE_PERIOD - 1);
    await registerSessionPresence(sessionId, ORIGIN);

    await sweepAfter(2 * GRACE_PERIOD);
    expect(session.killSessionByRawId).not.toHaveBeenCalled();
  });

  it('should only logout the session that lost its connections', async () => {
    const closedSessionId = nextSessionId();
    const openSessionId = nextSessionId();
    const connectionId = await registerSessionPresence(closedSessionId, ORIGIN) as string;
    await registerSessionPresence(openSessionId, ORIGIN);
    await unregisterSessionPresence(closedSessionId, connectionId);

    await sweepAfter(GRACE_PERIOD);
    expect(session.killSessionByRawId).toHaveBeenCalledExactlyOnceWith(closedSessionId);
  });

  it('should ignore an unknown or already closed connection', async () => {
    const sessionId = nextSessionId();
    const connectionId = await registerSessionPresence(sessionId, ORIGIN) as string;
    await unregisterSessionPresence(sessionId, connectionId);
    await unregisterSessionPresence(sessionId, connectionId);
    await unregisterSessionPresence(sessionId, 'unknown-connection');

    expect(store.removeSessionLease).toHaveBeenCalledOnce();
  });

  it('should keep a session whose tab is open on another node', async () => {
    const sessionId = nextSessionId();
    await openTabOnAnotherNode(sessionId);
    const connectionId = await registerSessionPresence(sessionId, ORIGIN) as string;
    await unregisterSessionPresence(sessionId, connectionId);

    await keepTabOpenOnAnotherNode(sessionId, 3 * LEASE_TTL);
    await logoutAbandonedSessions();
    expect(session.killSessionByRawId).not.toHaveBeenCalled();
  });

  it('should logout a session whose node crashed, once its leases expired', async () => {
    const sessionId = nextSessionId();
    // The other node crashes: its lease is never renewed nor removed
    await openTabOnAnotherNode(sessionId);

    await sweepAfter(LEASE_TTL + GRACE_PERIOD - 1);
    expect(session.killSessionByRawId).not.toHaveBeenCalled();

    await sweepAfter(1);
    expect(session.killSessionByRawId).toHaveBeenCalledExactlyOnceWith(sessionId);
  });

  it('should refuse a connection of a session being logged out', async () => {
    const sessionId = nextSessionId();
    const connectionId = await registerSessionPresence(sessionId, ORIGIN) as string;
    await unregisterSessionPresence(sessionId, connectionId);
    await sweepAfter(GRACE_PERIOD);
    expect(session.killSessionByRawId).toHaveBeenCalledOnce();

    expect(await registerSessionPresence(sessionId, ORIGIN)).toBeUndefined();
  });

  it('should stop tracking the sockets of a session logged out by another node', async () => {
    const sessionId = nextSessionId();
    const connectionId = await registerSessionPresence(sessionId, ORIGIN) as string;
    // Another node logged the session out (for instance after this node stalled): new leases are refused
    const saveSessionLeases = vi.mocked(store.saveSessionLeases).getMockImplementation();
    vi.mocked(store.saveSessionLeases).mockImplementation(async () => undefined);
    await vi.advanceTimersByTimeAsync(RENEW_INTERVAL);
    vi.mocked(store.saveSessionLeases).mockImplementation(saveSessionLeases!);

    await unregisterSessionPresence(sessionId, connectionId);
    expect(store.removeSessionLease).not.toHaveBeenCalled();
  });

  it('should not logout when the feature is disabled during the grace period, and release the session', async () => {
    const sessionId = nextSessionId();
    const connectionId = await registerSessionPresence(sessionId, ORIGIN) as string;
    await unregisterSessionPresence(sessionId, connectionId);
    enablePresence(false);

    await sweepAfter(GRACE_PERIOD);
    expect(session.killSessionByRawId).not.toHaveBeenCalled();
    expect(store.isDue(sessionId)).toBe(false);
    // Not marked as closing: the tab is tracked again as soon as it comes back
    expect(await registerSessionPresence(sessionId, ORIGIN)).toBeDefined();
  });

  it('should leave the time to reconnect to another node to the tabs of a stopping node', async () => {
    const sessionId = nextSessionId();
    const connectionId = await registerSessionPresence(sessionId, ORIGIN) as string;
    vi.mocked(getStoppingState).mockReturnValue(true);
    await unregisterSessionPresence(sessionId, connectionId);
    vi.mocked(getStoppingState).mockReturnValue(false);
    expect(store.removeSessionLease).not.toHaveBeenCalled();

    // The lease outlives the node: the tab reconnects to another node meanwhile,
    // and is still open when the lease of the stopped node would have logged the session out
    await vi.advanceTimersByTimeAsync(RENEW_INTERVAL);
    await keepTabOpenOnAnotherNode(sessionId, LEASE_TTL + GRACE_PERIOD);
    await logoutAbandonedSessions();
    expect(session.killSessionByRawId).not.toHaveBeenCalled();
  });

  it('should not publish a logout for a session already logged out or expired', async () => {
    storeSession(null);
    const sessionId = nextSessionId();
    const connectionId = await registerSessionPresence(sessionId, ORIGIN) as string;
    await unregisterSessionPresence(sessionId, connectionId);

    await sweepAfter(GRACE_PERIOD);
    expect(session.killSessionByRawId).not.toHaveBeenCalled();
    expect(listener.publishUserAction).not.toHaveBeenCalled();
    expect(store.isDue(sessionId)).toBe(false);
  });

  it('should check the session again when its logout fails', async () => {
    const sessionId = nextSessionId();
    const connectionId = await registerSessionPresence(sessionId, ORIGIN) as string;
    await unregisterSessionPresence(sessionId, connectionId);
    vi.mocked(session.killSessionByRawId).mockRejectedValueOnce(new Error('store unavailable'));

    await sweepAfter(GRACE_PERIOD);
    expect(store.isDue(sessionId)).toBe(true);

    await sweepAfter(5000);
    expect(session.killSessionByRawId).toHaveBeenCalledTimes(2);
    expect(listener.publishUserAction).toHaveBeenCalledOnce();
    expect(store.isDue(sessionId)).toBe(false);
  });

  it('should tell whether the session presence manager is enabled on at least one node', async () => {
    const listManagers = (...enabled: boolean[]) => {
      const nodes = enabled.map((enable, i) => ({ platform_id: `node-${i}`, managers: [{ id: SESSION_PRESENCE_MANAGER_ID, enable, running: enable }] }));
      vi.mocked(redis.getClusterInstances).mockResolvedValue(nodes as any);
    };
    listManagers(false, true);
    expect(await isSessionPresenceManagerEnabled()).toBe(true);
    listManagers(false, false);
    expect(await isSessionPresenceManagerEnabled()).toBe(false);
  });

  it('should logout on several nodes with the shared session store', async () => {
    listClusterNodes(true, true, true);
    expect(await isSessionPresenceSupported()).toBe(true);

    const sessionId = nextSessionId();
    const connectionId = await registerSessionPresence(sessionId, ORIGIN) as string;
    await unregisterSessionPresence(sessionId, connectionId);
    await sweepAfter(GRACE_PERIOD);
    expect(session.killSessionByRawId).toHaveBeenCalledExactlyOnceWith(sessionId);
  });

  describe('with sessions held in the memory of each node', () => {
    // The session store is read once, when the module is loaded
    const loadDomain = async () => {
      vi.resetModules();
      const domain = await import('../../../../src/modules/session/session-presence-domain');
      const { getClusterInstances } = await import('../../../../src/database/redis');
      const nodes = (...apiEnabledFlags: (boolean | undefined)[]) => {
        const instances = apiEnabledFlags.map((apiEnabled, i) => ({ platform_id: `node-${i}`, api_enabled: apiEnabled, managers: [] }));
        vi.mocked(getClusterInstances).mockResolvedValue(instances as any);
      };
      return { domain, nodes };
    };

    beforeAll(() => {
      sessionManager.value = 'local';
    });

    afterAll(() => {
      sessionManager.value = 'shared';
    });

    it('should only be supported while at most one node serves the API', async () => {
      const { domain, nodes } = await loadDomain();
      nodes(true, false);
      expect(await domain.isSessionPresenceSupported()).toBe(true);
      nodes(true, undefined);
      expect(await domain.isSessionPresenceSupported()).toBe(false);
    });

    it('should not logout while several nodes serve the API', async () => {
      const { domain, nodes } = await loadDomain();
      const { killSessionByRawId } = await import('../../../../src/database/session');
      const { getEntityFromCache } = await import('../../../../src/database/cache');
      vi.mocked(getEntityFromCache).mockResolvedValue({ platform_session_presence_enabled: true } as any);
      nodes(true, true);
      const sessionId = nextSessionId();
      const connectionId = await domain.registerSessionPresence(sessionId, ORIGIN) as string;
      await domain.unregisterSessionPresence(sessionId, connectionId);

      await vi.advanceTimersByTimeAsync(GRACE_PERIOD);
      await domain.logoutAbandonedSessions();
      expect(killSessionByRawId).not.toHaveBeenCalled();
      expect(store.isDue(sessionId)).toBe(false);
    });
  });

  it('should only publish context data fields that the activity index maps', async () => {
    // The mapping of the context data is strict: an unknown field makes the indexing of the event fail
    const sessionId = nextSessionId();
    const connectionId = await registerSessionPresence(sessionId, ORIGIN) as string;
    await unregisterSessionPresence(sessionId, connectionId);

    await sweepAfter(GRACE_PERIOD);
    const contextData = vi.mocked(listener.publishUserAction).mock.calls[0][0].context_data as object;
    const contextDataAttribute = schemaAttributesDefinition.getAttribute(ENTITY_TYPE_ACTIVITY, 'context_data') as ObjectAttribute;
    const mappedFields = contextDataAttribute.mappings.map(({ name }) => name);
    expect(Object.keys(contextData)).toEqual(['reason']);
    Object.keys(contextData).forEach((field) => expect(mappedFields).toContain(field));
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
      await onSessionPresenceClose(ctx);
      await sweepAfter(GRACE_PERIOD);

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
      await onSessionPresenceClose(ctx);
      await sweepAfter(GRACE_PERIOD);

      expect(session.killSessionByRawId).toHaveBeenCalledExactlyOnceWith(sessionId);
    });

    it('should neither track nor logout without the SESSION_PRESENCE feature flag', async () => {
      vi.mocked(isFeatureEnabled).mockReturnValue(false);
      mockSessionMiddleware(nextSessionId(), { user: USER });
      const ctx = buildContext();

      await onSessionPresenceConnect(ctx);
      await onSessionPresenceClose(ctx);
      await sweepAfter(GRACE_PERIOD);

      expect(session.getSessionMiddleware).not.toHaveBeenCalled();
      expect(session.killSessionByRawId).not.toHaveBeenCalled();
    });

    it('should not logout a session tracked before the feature flag was disabled', async () => {
      const sessionId = nextSessionId();
      const connectionId = await registerSessionPresence(sessionId, ORIGIN) as string;
      vi.mocked(isFeatureEnabled).mockReturnValue(false);
      await unregisterSessionPresence(sessionId, connectionId);
      await sweepAfter(GRACE_PERIOD);

      expect(session.killSessionByRawId).not.toHaveBeenCalled();
    });

    it('should not track an unauthenticated socket', async () => {
      mockSessionMiddleware(nextSessionId(), {});
      const ctx = buildContext();

      await onSessionPresenceConnect(ctx);
      await onSessionPresenceClose(ctx);

      expect(store.saveSessionLeases).not.toHaveBeenCalled();
    });

    it('should not track a socket closed while its session was parsed', async () => {
      mockSessionMiddleware(nextSessionId(), { user: USER });
      const ctx = buildContext(CLOSED);

      await onSessionPresenceConnect(ctx);
      await onSessionPresenceClose(ctx);

      expect(store.saveSessionLeases).not.toHaveBeenCalled();
    });

    it('should release a socket closed while it was registered', async () => {
      const sessionId = nextSessionId();
      mockSessionMiddleware(sessionId, { user: USER });
      const ctx = buildContext();
      // The close hook runs while the lease is written: it finds nothing to unregister
      vi.mocked(store.saveSessionLeases).mockImplementationOnce(async () => {
        ctx.extra.socket.readyState = CLOSED;
        await onSessionPresenceClose(ctx);
        return Date.now() + LEASE_TTL;
      });

      await onSessionPresenceConnect(ctx);
      expect(store.removeSessionLease).toHaveBeenCalledOnce();
    });

    it('should accept the socket even if the presence fails', async () => {
      vi.mocked(session.getSessionMiddleware).mockRejectedValue(new Error('store unavailable'));

      await expect(onSessionPresenceConnect(buildContext())).resolves.toBeUndefined();
    });
  });
});
