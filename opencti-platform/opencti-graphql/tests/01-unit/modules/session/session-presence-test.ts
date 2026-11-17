import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { isSessionPresenceSupported, registerSessionPresence, unregisterSessionPresence } from '../../../../src/modules/session/session-presence-domain';
import { onSessionPresenceClose, onSessionPresenceConnect } from '../../../../src/modules/session/session-presence-ws';
import * as session from '../../../../src/database/session';
import * as redis from '../../../../src/database/redis';
import * as userDomain from '../../../../src/modules/user/user-domain';
import { getStoppingState, isFeatureEnabled } from '../../../../src/config/conf';

const { GRACE_PERIOD, LEASE_TTL } = vi.hoisted(() => ({ GRACE_PERIOD: 30000, LEASE_TTL: 30000 }));
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
    checkTime: (sessionId: string) => due.get(sessionId),
    hasLiveLease: (sessionId: string, connectionId: string) => (leases.get(sessionId)?.get(connectionId) ?? 0) > now(),
    // Another node logging the session out
    markClosing: (sessionId: string, closingTtl: number) => {
      leases.delete(sessionId);
      closing.set(sessionId, now() + closingTtl);
    },
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

vi.mock('../../../../src/database/session', () => ({
  getSessionMiddleware: vi.fn(),
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
        return actual.default.get(key);
      }),
    },
    getStoppingState: vi.fn(() => false),
    isFeatureEnabled: vi.fn(() => true),
    logApp: { ...actual.logApp, error: vi.fn(), warn: vi.fn() },
  };
});

const USER = { id: 'user-id', groups: [{ internal_id: 'group-id' }], organizations: [] };
const ORIGIN = { socket: 'query', user_id: USER.id };

// The connections of this node live as long as the module: every test works on its own session id
let sessionCounter = 0;
const nextSessionId = () => {
  sessionCounter += 1;
  return `session-${sessionCounter}`;
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

  it('should ignore an unknown or already closed connection', async () => {
    const sessionId = nextSessionId();
    const connectionId = await registerSessionPresence(sessionId, ORIGIN) as string;
    await unregisterSessionPresence(sessionId, connectionId);
    await unregisterSessionPresence(sessionId, connectionId);
    await unregisterSessionPresence(sessionId, 'unknown-connection');

    expect(store.removeSessionLease).toHaveBeenCalledOnce();
  });

  it('should leave the lease of a stopping node to expire, so that its tabs can reconnect to another node', async () => {
    const sessionId = nextSessionId();
    const connectionId = await registerSessionPresence(sessionId, ORIGIN) as string;
    vi.mocked(getStoppingState).mockReturnValue(true);
    await unregisterSessionPresence(sessionId, connectionId);

    expect(store.removeSessionLease).not.toHaveBeenCalled();
    expect(store.checkTime(sessionId)).toEqual(Date.now() + LEASE_TTL + GRACE_PERIOD);
  });

  it('should refuse a connection of a session being logged out', async () => {
    const sessionId = nextSessionId();
    store.markClosing(sessionId, 60000);

    expect(await registerSessionPresence(sessionId, ORIGIN)).toBeUndefined();
    expect(store.checkTime(sessionId)).toBeUndefined();
  });

  it('should stop tracking the sockets of a session logged out by another node', async () => {
    const sessionId = nextSessionId();
    const connectionId = await registerSessionPresence(sessionId, ORIGIN) as string;
    store.markClosing(sessionId, 60000);
    await vi.advanceTimersByTimeAsync(RENEW_INTERVAL);

    await unregisterSessionPresence(sessionId, connectionId);
    expect(store.removeSessionLease).not.toHaveBeenCalled();
  });

  it('should only be supported while at most one node serves the API', async () => {
    const listClusterNodes = (...apiEnabledFlags: (boolean | undefined)[]) => {
      const nodes = apiEnabledFlags.map((apiEnabled, i) => ({ platform_id: `node-${i}`, api_enabled: apiEnabled, managers: [] }));
      vi.mocked(redis.getClusterInstances).mockResolvedValue(nodes as any);
    };
    listClusterNodes(true, false);
    expect(await isSessionPresenceSupported()).toBe(true);
    listClusterNodes(true, undefined);
    expect(await isSessionPresenceSupported()).toBe(false);
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
      expect(userDomain.userWithOrigin).toHaveBeenCalledWith(ctx.extra.request, USER);
      expect(await store.findSessionOrigin(sessionId)).toEqual({ socket: 'query', ip: '10.0.0.1', user_id: USER.id });

      await onSessionPresenceClose(ctx);
      expect(store.removeSessionLease).toHaveBeenCalledOnce();
      expect(store.checkTime(sessionId)).toEqual(Date.now() + GRACE_PERIOD);
    });

    it('should not track anything without the SESSION_PRESENCE feature flag', async () => {
      vi.mocked(isFeatureEnabled).mockReturnValue(false);
      mockSessionMiddleware(nextSessionId(), { user: USER });
      const ctx = buildContext();

      await onSessionPresenceConnect(ctx);
      await onSessionPresenceClose(ctx);

      expect(session.getSessionMiddleware).not.toHaveBeenCalled();
      expect(store.saveSessionLeases).not.toHaveBeenCalled();
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
